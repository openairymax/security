// SPDX-License-Identifier: GPL-2.0-only
/*
 * rc_test.c — IPC 控制面 Reconciliation 的 TAP 测试
 *
 * 职责：
 *   用假时钟与记录式 ops 覆盖 Ring/Capability
 *   差异、冲突优先级、动作顺序、消息 TTL 边界、
 *   回调失败继续执行、三阶段超时降级、容量上限
 *   与空输入幂等。自包含，不依赖外部框架。
 *
 * 文档锚点：
 * docs/docs-linux/110-security/
 * 05-ipc-control-plane-reconciliation.md §6。
 */
#include "rc_api.h"
#include "rc_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

enum {
	OP_REC,
	OP_DROP,
	OP_ADOPT,
	OP_CHECK,
	OP_REVOKE,
	OP_SEND,
	OP_MSGDROP,
	OP_DEGRADE
};

struct call {
	int op;
	__u32 a;
	unsigned b;
	__u64 c;
};

static struct call g_calls[256];
static size_t g_ncalls;
static int g_rec_ret;
static int g_drop_ret;
static int g_adopt_ret;
static int g_check_ret;
static int g_revoke_ret;
static int g_send_ret;
static int g_msgdrop_ret;
static int g_drop_fail;

static __u64 g_clk[32];
static size_t g_clk_n;
static size_t g_clk_i;

static int g_total;
static int g_fail;

static void ok(int cond, const char *name)
{
	g_total++;
	if (!cond)
		g_fail++;
	printf("%s %d - %s\n", cond ? "ok" : "not ok", g_total, name);
}

static void rec(int op, __u32 a, unsigned b, __u64 c)
{
	if (g_ncalls >= sizeof(g_calls) / sizeof(g_calls[0]))
		return;
	g_calls[g_ncalls].op = op;
	g_calls[g_ncalls].a = a;
	g_calls[g_ncalls].b = b;
	g_calls[g_ncalls].c = c;
	g_ncalls++;
}

static void reset_ops(void)
{
	memset(g_calls, 0, sizeof(g_calls));
	g_ncalls = 0;
	g_rec_ret = 0;
	g_drop_ret = 0;
	g_adopt_ret = 0;
	g_check_ret = 0;
	g_revoke_ret = 0;
	g_send_ret = 0;
	g_msgdrop_ret = 0;
	g_drop_fail = 0;
}

static __u64 fake_now(void)
{
	if (g_clk_i < g_clk_n)
		return g_clk[g_clk_i++];
	if (g_clk_n == 0)
		return 0;
	return g_clk[g_clk_n - 1];
}

static void set_clock(const __u64 *v, size_t n)
{
	memcpy(g_clk, v, n * sizeof(*v));
	g_clk_n = n;
	g_clk_i = 0;
}

static int op_rec(__u32 id)
{
	rec(OP_REC, id, 0, 0);
	return g_rec_ret;
}

static int op_drop(__u32 id)
{
	rec(OP_DROP, id, 0, 0);
	if (g_drop_fail)
		return id == 1 ? -EIO : -EACCES;
	return g_drop_ret;
}

static int op_adopt(__u32 id, __u8 state)
{
	rec(OP_ADOPT, id, state, 0);
	return g_adopt_ret;
}

static int op_check(__u32 id)
{
	rec(OP_CHECK, id, 0, 0);
	return g_check_ret;
}

static int op_revoke(__u32 id)
{
	rec(OP_REVOKE, id, 0, 0);
	return g_revoke_ret;
}

static int op_send(__u32 ring, __u64 ts)
{
	rec(OP_SEND, ring, 0, ts);
	return g_send_ret;
}

static int op_msgdrop(__u32 ring, __u64 ts)
{
	rec(OP_MSGDROP, ring, 0, ts);
	return g_msgdrop_ret;
}

static void op_degrade(int why)
{
	rec(OP_DEGRADE, 0, (unsigned)why, 0);
}

static const struct rc_ops test_ops = {
	.ring_rec = op_rec,
	.ring_drop = op_drop,
	.ring_adopt = op_adopt,
	.cap_check = op_check,
	.cap_revoke = op_revoke,
	.msg_send = op_send,
	.msg_drop = op_msgdrop,
	.degrade = op_degrade,
};

static struct rc_ctx mkctx(void)
{
	struct rc_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ops = &test_ops;
	ctx.now_ns = fake_now;
	return ctx;
}

static void test_ring_detect(void)
{
	struct rc_ring st[] = {
		{ 2, 1 }, { 1, 1 }, { 1, 1 }, { 4, 1 },
	};
	struct rc_ring sc[] = {
		{ 1, 1 }, { 3, 2 }, { 3, 2 }, { 4, 2 },
	};
	struct rc_ctx ctx = mkctx();
	struct rc_scan s;
	struct rc_diff d[16];
	size_t n = 0;

	ctx.state_rings = st;
	ctx.state_rings_nr = sizeof(st) / sizeof(st[0]);
	ctx.scan_rings = sc;
	ctx.scan_rings_nr = sizeof(sc) / sizeof(sc[0]);
	ok(rc_scan_build(&ctx, &s) == 0, "ring 快照构建");
	ok(rc_detect(&s, d, 16, &n) == 0, "ring 差异检测");
	ok(n == 3, "ring 重复项去重后为 3 条");
	ok(d[0].id == 2 && d[0].type == RC_MISS, "id2 MISS");
	ok(d[1].id == 3 && d[1].type == RC_NEW && d[1].data == 2,
	   "id3 NEW 取数据面状态");
	ok(d[2].id == 4 && d[2].type == RC_CONF &&
	   d[2].data == 2 && d[2].cp == 1, "id4 CONF 双方状态");
	rc_scan_free(&s);
}

static void test_cap_detect(void)
{
	struct rc_cap st[] = {
		{ 10, 2, 1 }, { 12, 1, 1 },
	};
	struct rc_cap sc[] = {
		{ 10, 1, 1 }, { 11, 1, 0 },
	};
	struct rc_ctx ctx = mkctx();
	struct rc_scan s;
	struct rc_diff d[16];
	size_t n = 0;

	ctx.state_caps = st;
	ctx.state_caps_nr = sizeof(st) / sizeof(st[0]);
	ctx.scan_caps = sc;
	ctx.scan_caps_nr = sizeof(sc) / sizeof(sc[0]);
	ok(rc_scan_build(&ctx, &s) == 0, "cap 快照构建");
	ok(rc_detect(&s, d, 16, &n) == 0, "cap 差异检测");
	ok(n == 2, "cap 差异为 2 条");
	ok(d[0].id == 10 && d[0].type == RC_REVOKE, "id10 REVOKE");
	ok(d[1].id == 11 && d[1].type == RC_VERIFY, "id11 VERIFY");
	rc_scan_free(&s);
}

static void test_conflict_order(void)
{
	struct rc_ring st[] = {
		{ 5, 1 }, { 9, 1 },
	};
	struct rc_ring sc[] = {
		{ 1, 2 }, { 5, 2 },
	};
	struct rc_ctx ctx = mkctx();
	static const __u64 clk[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int ret;

	reset_ops();
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ctx.state_rings = st;
	ctx.state_rings_nr = sizeof(st) / sizeof(st[0]);
	ctx.scan_rings = sc;
	ctx.scan_rings_nr = sizeof(sc) / sizeof(sc[0]);
	ret = rc_run(&ctx);
	ok(ret == 0, "冲突场景执行成功");
	ok(g_ncalls == 3, "按 id 升序执行 3 个动作");
	ok(g_calls[0].op == OP_REC && g_calls[0].a == 1, "先 NEW id1");
	ok(g_calls[1].op == OP_ADOPT && g_calls[1].a == 5 &&
	   g_calls[1].b == 2, "再 CONF id5 采用数据面状态");
	ok(g_calls[2].op == OP_DROP && g_calls[2].a == 9, "最后 MISS id9");
	ok(ctx.report.rings_new == 1 && ctx.report.rings_conf == 1 &&
	   ctx.report.rings_miss == 1, "报告分类计数正确");
}

static void test_msg_ttl(void)
{
	__u64 now = 1000000000000ULL;
	struct rc_msg m[] = {
		{ 1, RC_MSG_NORMAL, 0 },
		{ 2, RC_MSG_NORMAL, 0 },
		{ 3, RC_MSG_CAP, 0 },
		{ 4, RC_MSG_CTRL, 0 },
		{ 5, RC_MSG_CTRL, 0 },
	};
	struct rc_ctx ctx = mkctx();
	static const __u64 clk[] = {
		1000000000000ULL, 1000000000000ULL, 1000000000000ULL,
		1000000000000ULL, 1000000000000ULL, 1000000000000ULL,
		1000000000000ULL, 1000000000000ULL,
	};
	int ret;

	reset_ops();
	m[0].ts_ns = now - RC_TTL_NORMAL_NS;
	m[1].ts_ns = now - RC_TTL_NORMAL_NS - 1;
	m[2].ts_ns = now - RC_TTL_CAP_NS;
	m[3].ts_ns = now - RC_TTL_CTRL_NS;
	m[4].ts_ns = now - RC_TTL_CTRL_NS - 1;
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ctx.msgs = m;
	ctx.msgs_nr = sizeof(m) / sizeof(m[0]);
	ret = rc_run(&ctx);
	ok(ret == 0, "消息 TTL 场景执行成功");
	ok(g_ncalls == 5, "每条消息触发一次动作");
	ok(g_calls[0].op == OP_SEND && g_calls[0].a == 1,
	   "恰好等于 TTL 时补发");
	ok(g_calls[1].op == OP_MSGDROP && g_calls[1].a == 2,
	   "超过 TTL 时丢弃");
	ok(g_calls[2].op == OP_SEND && g_calls[2].a == 3,
	   "Capability 恰好等于 TTL 时补发");
	ok(g_calls[3].op == OP_SEND && g_calls[3].a == 4,
	   "控制指令恰好等于 TTL 时补发");
	ok(g_calls[4].op == OP_MSGDROP && g_calls[4].a == 5,
	   "控制指令超过 TTL 时丢弃");
	ok(ctx.report.msg_sent == 3 && ctx.report.msg_drop == 2,
	   "补发与丢弃计数正确");
}

static void test_failure_continue(void)
{
	struct rc_ring st[] = {
		{ 1, 1 }, { 2, 1 },
	};
	struct rc_ctx ctx = mkctx();
	static const __u64 clk[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int ret;

	reset_ops();
	g_drop_fail = 1;
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ctx.state_rings = st;
	ctx.state_rings_nr = sizeof(st) / sizeof(st[0]);
	ret = rc_run(&ctx);
	ok(ret == -EIO, "返回首个回调错误");
	ok(g_ncalls == 2, "首个失败后仍执行后续动作");
	ok(ctx.report.failed == 2 && ctx.report.acted == 0,
	   "失败计数累计");
}

static void test_verify_failure(void)
{
	struct rc_cap st[] = { { 20, 1, 1 } };
	struct rc_cap sc[] = { { 20, 1, 0 } };
	struct rc_ctx ctx = mkctx();
	static const __u64 clk[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int ret;

	reset_ops();
	g_check_ret = -EACCES;
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ctx.state_caps = st;
	ctx.state_caps_nr = 1;
	ctx.scan_caps = sc;
	ctx.scan_caps_nr = 1;
	ret = rc_run(&ctx);
	ok(ret == -EACCES, "校验失败返回该错误");
	ok(g_ncalls == 2 && g_calls[0].op == OP_CHECK &&
	   g_calls[1].op == OP_REVOKE, "校验失败后撤销 capability");
	ok(ctx.report.caps_verify == 1, "VERIFY 差异计数正确");
}

static void test_verify_ok(void)
{
	struct rc_cap st[] = { { 30, 1, 1 } };
	struct rc_cap sc[] = { { 30, 1, 0 } };
	struct rc_ctx ctx = mkctx();
	static const __u64 clk[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int ret;

	reset_ops();
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ctx.state_caps = st;
	ctx.state_caps_nr = 1;
	ctx.scan_caps = sc;
	ctx.scan_caps_nr = 1;
	ret = rc_run(&ctx);
	ok(ret == 0, "校验成功执行成功");
	ok(g_ncalls == 1 && g_calls[0].op == OP_CHECK,
	   "校验成功后不再撤销");
	ok(ctx.report.acted == 1, "成功动作计数正确");
}

static void test_scan_timeout(void)
{
	struct rc_ctx ctx = mkctx();
	static const __u64 clk[] = {
		0, 0, 6000000000ULL, 6000000000ULL, 12000000000ULL,
		12000000000ULL, 12000000000ULL, 12000000000ULL,
		12000000000ULL, 12000000000ULL,
	};
	int ret;

	reset_ops();
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ret = rc_run(&ctx);
	ok(ret == 0, "扫描超时仍完成本轮");
	ok(g_clk_i == 10, "扫描超预算后重试一次");
	ok(ctx.degrade == 1 && ctx.report.degrade == 1,
	   "扫描重试仍超时置降级");
	ok(g_ncalls == 1 && g_calls[0].op == OP_DEGRADE &&
	   g_calls[0].b == RC_DEGRADE_TIMEOUT, "降级回调被调用");
	ok(ctx.report.retry_ns == RC_RETRY_NS, "写回 60s 重试间隔");
}

static void test_detect_timeout(void)
{
	struct rc_ctx ctx = mkctx();
	static const __u64 clk[] = {
		0, 0, 0, 0, 11000000000ULL, 11000000000ULL,
		11000000000ULL, 11000000000ULL,
	};
	int ret;

	reset_ops();
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ret = rc_run(&ctx);
	ok(ret == 0, "检测超时仍完成本轮");
	ok(ctx.degrade == 1 && g_ncalls == 1 &&
	   g_calls[0].op == OP_DEGRADE, "检测超 10s 降级");
}

static void test_fix_timeout(void)
{
	struct rc_ctx ctx = mkctx();
	static const __u64 clk[] = {
		0, 0, 0, 0, 0, 0, 16000000000ULL, 16000000000ULL,
	};
	int ret;

	reset_ops();
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ret = rc_run(&ctx);
	ok(ret == 0, "修复超时仍完成本轮");
	ok(ctx.degrade == 1 && g_ncalls == 1 &&
	   g_calls[0].op == OP_DEGRADE, "修复超 15s 降级");
}

static void test_total_timeout(void)
{
	struct rc_ctx ctx = mkctx();
	static const __u64 clk[] = {
		0, 0, 2000000000ULL, 2000000000ULL, 10000000000ULL,
		10000000000ULL, 20000000000ULL, 31000000000ULL,
	};
	int ret;

	reset_ops();
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ret = rc_run(&ctx);
	ok(ret == 0, "总预算超时仍完成本轮");
	ok(ctx.degrade == 1 && g_ncalls == 1 &&
	   g_calls[0].op == OP_DEGRADE, "总预算超 30s 降级");
}

static void test_normal(void)
{
	struct rc_ctx ctx = mkctx();
	static const __u64 clk[] = {
		0, 0, 1000000000ULL, 2000000000ULL,
		3000000000ULL, 4000000000ULL, 5000000000ULL,
		6000000000ULL,
	};
	int ret;

	reset_ops();
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ret = rc_run(&ctx);
	ok(ret == 0, "预算内执行成功");
	ok(g_ncalls == 0 && ctx.degrade == 0 &&
	   ctx.report.degrade == 0, "正常完成不降级");
	ok(ctx.report.retry_ns == 0, "正常完成清空重试间隔");
}

static struct rc_ring g_big_rings[RC_MAX_ENTRIES + 1];
static struct rc_cap g_big_caps[RC_MAX_ENTRIES + 1];

static void test_capacity(void)
{
	struct rc_ctx ctx = mkctx();
	int ret;

	reset_ops();
	set_clock(NULL, 0);
	ctx.state_rings = g_big_rings;
	ctx.state_rings_nr = RC_MAX_ENTRIES + 1;
	ret = rc_run(&ctx);
	ok(ret == -E2BIG, "Ring 输入超上限返回 -E2BIG");

	ctx = mkctx();
	reset_ops();
	set_clock(NULL, 0);
	ctx.state_caps = g_big_caps;
	ctx.state_caps_nr = RC_MAX_ENTRIES + 1;
	ret = rc_run(&ctx);
	ok(ret == -E2BIG, "Capability 输入超上限返回 -E2BIG");
}

static void test_empty(void)
{
	struct rc_ctx ctx = mkctx();
	static const __u64 clk[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int ret;

	reset_ops();
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ret = rc_run(&ctx);
	ok(ret == 0 && g_ncalls == 0, "空输入不产生动作");
	ok(ctx.report.rings_new == 0 && ctx.report.msg_sent == 0 &&
	   ctx.degrade == 0, "空输入计数全零");
	set_clock(clk, sizeof(clk) / sizeof(clk[0]));
	ret = rc_run(&ctx);
	ok(ret == 0 && g_ncalls == 0 && ctx.report.acted == 0,
	   "空输入重复执行幂等");
}

int main(void)
{
	printf("TAP version 13\n");
	test_ring_detect();
	test_cap_detect();
	test_conflict_order();
	test_msg_ttl();
	test_failure_continue();
	test_verify_failure();
	test_verify_ok();
	test_scan_timeout();
	test_detect_timeout();
	test_fix_timeout();
	test_total_timeout();
	test_normal();
	test_capacity();
	test_empty();
	printf("1..%d\n", g_total);
	return g_fail == 0 ? 0 : 1;
}

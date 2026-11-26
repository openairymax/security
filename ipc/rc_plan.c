// SPDX-License-Identifier: GPL-2.0-only
/*
 * rc_plan.c — 差异到动作的映射与执行
 *
 * 职责：
 *   把 rc_diff 序列映射为 ring_rec / ring_drop /
 *   ring_adopt / cap_check / cap_revoke，并按 TTL
 *   补发或丢弃暂存消息。任一回调返回负值时记录
 *   首个错误并继续执行其余动作，保证最终一致。
 *
 * 文档锚点：
 * docs/docs-linux/110-security/
 * 05-ipc-control-plane-reconciliation.md §4。
 */
#include "rc_internal.h"

static __u64 msg_ttl(__u8 kind)
{
	switch (kind) {
	case RC_MSG_CAP:
		return RC_TTL_CAP_NS;
	case RC_MSG_CTRL:
		return RC_TTL_CTRL_NS;
	default:
		return RC_TTL_NORMAL_NS;
	}
}

static int msg_expired(__u64 now, __u64 ts, __u64 ttl)
{
	if (now <= ts)
		return 0;
	return now - ts > ttl;
}

static int record(struct rc_report *rep, int ret)
{
	if (ret < 0) {
		rep->failed++;
		return ret;
	}
	rep->acted++;
	return 0;
}

/*
 * cap_check 返回 0 视为已校验；非 0 视为校验
 * 失败，保守地再撤销一次。负值同时记为回调
 * 错误，但撤销动作仍要执行。
 */
static int do_verify(struct rc_ctx *ctx, const struct rc_diff *d,
		     struct rc_report *rep)
{
	int first = 0;
	int ret = ctx->ops->cap_check(d->id);

	if (ret == 0) {
		rep->acted++;
		return 0;
	}
	if (ret < 0) {
		rep->failed++;
		first = ret;
	}
	ret = ctx->ops->cap_revoke(d->id);
	if (ret < 0) {
		rep->failed++;
		if (first == 0)
			first = ret;
	} else {
		rep->acted++;
	}
	return first;
}

static int do_diff(struct rc_ctx *ctx, const struct rc_diff *d,
		   struct rc_report *rep)
{
	switch (d->type) {
	case RC_NEW:
		rep->rings_new++;
		return record(rep, ctx->ops->ring_rec(d->id));
	case RC_MISS:
		rep->rings_miss++;
		return record(rep, ctx->ops->ring_drop(d->id));
	case RC_CONF:
		rep->rings_conf++;
		return record(rep, ctx->ops->ring_adopt(d->id, d->data));
	case RC_VERIFY:
		rep->caps_verify++;
		return do_verify(ctx, d, rep);
	case RC_REVOKE:
		rep->caps_revoke++;
		return record(rep, ctx->ops->cap_revoke(d->id));
	default:
		return 0;
	}
}

static int apply_diffs(struct rc_ctx *ctx, const struct rc_plan *plan,
		       struct rc_report *rep)
{
	size_t i;
	int first = 0;

	for (i = 0; i < plan->nr; i++) {
		int ret = do_diff(ctx, &plan->diff[i], rep);

		if (first == 0 && ret < 0)
			first = ret;
	}
	return first;
}

static int apply_msgs(struct rc_ctx *ctx, struct rc_report *rep,
		      __u64 now)
{
	size_t i;
	int first = 0;

	for (i = 0; i < ctx->msgs_nr; i++) {
		const struct rc_msg *m = &ctx->msgs[i];
		int ret;

		if (msg_expired(now, m->ts_ns, msg_ttl(m->kind))) {
			rep->msg_drop++;
			ret = ctx->ops->msg_drop(m->ring, m->ts_ns);
		} else {
			rep->msg_sent++;
			ret = ctx->ops->msg_send(m->ring, m->ts_ns);
		}
		if (ret < 0) {
			rep->failed++;
			if (first == 0)
				first = ret;
		} else {
			rep->acted++;
		}
	}
	return first;
}

int rc_apply(struct rc_ctx *ctx, const struct rc_plan *plan, __u64 now)
{
	struct rc_report *rep = &ctx->report;
	int first = apply_diffs(ctx, plan, rep);
	int ret = apply_msgs(ctx, rep, now);

	if (first == 0)
		first = ret;
	return first;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * rc_loop.c — 三阶段预算调度与降级
 *
 * 职责：
 *   扫描 5s（超预算重试一次）、检测 10s、
 *   修复 15s，总预算 30s。阶段耗时由注入
 *   时钟在调用前后取样得出；扫描重试仍超
 *   预算或任一阶段/总预算超时即置 degrade，
 *   并回调 ops->degrade。下一次调度间隔写回
 *   report.retry_ns，库内不 sleep。
 *
 * 文档锚点：
 * docs/docs-linux/110-security/
 * 05-ipc-control-plane-reconciliation.md §5。
 */
#include "rc_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int scan_phase(struct rc_ctx *ctx, struct rc_scan *scan,
		      __u8 *degrade)
{
	__u64 t0 = ctx->now_ns();
	__u64 t1;
	int ret = rc_scan_build(ctx, scan);

	t1 = ctx->now_ns();
	if (ret < 0)
		return ret;
	if (t1 - t0 <= RC_SCAN_BUDGET_NS)
		return 0;
	rc_scan_free(scan);
	t0 = ctx->now_ns();
	ret = rc_scan_build(ctx, scan);
	t1 = ctx->now_ns();
	if (ret < 0)
		return ret;
	if (t1 - t0 > RC_SCAN_BUDGET_NS)
		*degrade = 1;
	return 0;
}

static void report_degrade(struct rc_ctx *ctx, __u8 degrade)
{
	if (!degrade) {
		ctx->degrade = 0;
		ctx->report.degrade = 0;
		ctx->report.retry_ns = 0;
		return;
	}
	ctx->degrade = 1;
	ctx->report.degrade = 1;
	ctx->report.retry_ns = RC_RETRY_NS;
	if (ctx->ops->degrade != NULL)
		ctx->ops->degrade(RC_DEGRADE_TIMEOUT);
}

int rc_run(struct rc_ctx *ctx)
{
	struct rc_scan scan = { 0 };
	struct rc_plan plan;
	struct rc_diff *diffs;
	__u64 start;
	__u64 t0;
	__u64 t1;
	__u8 degrade = 0;
	size_t nr = 0;
	int first;
	int ret;

	if (ctx == NULL || ctx->ops == NULL || ctx->now_ns == NULL)
		return -EINVAL;
	memset(&ctx->report, 0, sizeof(ctx->report));
	ctx->degrade = 0;

	diffs = malloc(RC_DIFF_MAX * sizeof(*diffs));
	if (diffs == NULL)
		return -ENOMEM;
	plan.diff = diffs;
	plan.nr = 0;
	plan.degrade = 0;
	plan.retry_ns = 0;

	start = ctx->now_ns();
	ret = scan_phase(ctx, &scan, &degrade);
	if (ret < 0)
		goto out;

	t0 = ctx->now_ns();
	ret = rc_detect(&scan, diffs, RC_DIFF_MAX, &nr);
	t1 = ctx->now_ns();
	if (ret < 0)
		goto out_free;
	if (t1 - t0 > RC_DETECT_BUDGET_NS)
		degrade = 1;

	plan.nr = nr;
	t0 = ctx->now_ns();
	first = rc_apply(ctx, &plan, t0);
	t1 = ctx->now_ns();
	if (t1 - t0 > RC_FIX_BUDGET_NS)
		degrade = 1;
	if (ctx->now_ns() - start > RC_TOTAL_BUDGET_NS)
		degrade = 1;

	ctx->report.error = first;
	report_degrade(ctx, degrade);
	ret = first;

out_free:
	rc_scan_free(&scan);
out:
	free(diffs);
	return ret;
}

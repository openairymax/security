// SPDX-License-Identifier: GPL-2.0-only
/*
 * rc_internal.h — 差异检测与动作执行的内部接口
 *
 * 职责：
 *   rc_scan_build 做输入校验、容量检查与按 id
 *   排序的去重快照；rc_detect 用双指针归并；
 *   rc_apply 执行差异与暂存消息动作。
 *   仅供 rc_diff.c / rc_plan.c / rc_loop.c 与
 *   单元测试使用。
 *
 * 文档锚点：
 * docs/docs-linux/110-security/
 * 05-ipc-control-plane-reconciliation.md §3、§4。
 */
#ifndef AIRY_IPC_RC_INTERNAL_H
#define AIRY_IPC_RC_INTERNAL_H

#include "rc_api.h"

/* 排序后的输入快照，四个数组均由 rc_scan_build 分配 */
struct rc_scan {
	struct rc_ring *state_rings;
	size_t state_rings_nr;
	struct rc_ring *scan_rings;
	size_t scan_rings_nr;
	struct rc_cap *state_caps;
	size_t state_caps_nr;
	struct rc_cap *scan_caps;
	size_t scan_caps_nr;
};

int rc_scan_build(const struct rc_ctx *ctx, struct rc_scan *scan);
void rc_scan_free(struct rc_scan *scan);
int rc_detect(struct rc_scan *scan, struct rc_diff *out, size_t cap,
	      size_t *nr);
int rc_apply(struct rc_ctx *ctx, const struct rc_plan *plan, __u64 now);

#endif /* AIRY_IPC_RC_INTERNAL_H */

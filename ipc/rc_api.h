// SPDX-License-Identifier: GPL-2.0-only
/*
 * rc_api.h — IPC 控制面 Reconciliation 的纯数据接口
 *
 * 职责：
 *   定义控制面快照、数据面扫描结果、差异、
 *   动作计划、执行回调与单调时钟注入点。
 *   本头文件不引用任何内核头，可脱离内核在
 *   用户态直接构造输入并单测。
 *
 * 差异模型与修复策略见
 * docs/docs-linux/110-security/
 * 05-ipc-control-plane-reconciliation.md §3、§4。
 */
#ifndef AIRY_IPC_RC_API_H
#define AIRY_IPC_RC_API_H

#include <stddef.h>
#include <stdint.h>

/*
 * 与内核 UAPI 同名的定宽类型。这里自行定义是为了
 * 让本库不依赖 <linux/types.h>，用户态与内核侧
 * 共享同一份字段布局。
 */
typedef uint32_t __u32;
typedef uint8_t __u8;
typedef uint64_t __u64;

/* 差异类型：Ring 三类 + Capability 两类 */
#define RC_NEW    0u
#define RC_MISS   1u
#define RC_CONF   2u
#define RC_VERIFY 3u
#define RC_REVOKE 4u

/* 待补发消息类别 */
#define RC_MSG_NORMAL 0u
#define RC_MSG_CAP    1u
#define RC_MSG_CTRL   2u

/* Capability state 中表示「已撤销」的取值 */
#define RC_CAP_REVOKED 2u

/* 降级原因 */
#define RC_DEGRADE_NONE    0
#define RC_DEGRADE_TIMEOUT 1

/* 单类输入容量上限，超过返回 -E2BIG，不静默截断 */
#define RC_MAX_ENTRIES 1024u
/* 差异上限：两类输入各最多 2 组，共 4096 项 */
#define RC_DIFF_MAX (4u * RC_MAX_ENTRIES)

/* 暂存消息 TTL：普通 30s、Capability 60s、控制指令 10s */
#define RC_TTL_NORMAL_NS (30ULL * 1000000000ULL)
#define RC_TTL_CAP_NS    (60ULL * 1000000000ULL)
#define RC_TTL_CTRL_NS   (10ULL * 1000000000ULL)

/* 三阶段预算与总预算，单位 ns */
#define RC_SCAN_BUDGET_NS   (5ULL * 1000000000ULL)
#define RC_DETECT_BUDGET_NS (10ULL * 1000000000ULL)
#define RC_FIX_BUDGET_NS    (15ULL * 1000000000ULL)
#define RC_TOTAL_BUDGET_NS  (30ULL * 1000000000ULL)
/* 超预算后的重试间隔，由调用方读取，库内不 sleep */
#define RC_RETRY_NS (60ULL * 1000000000ULL)

struct rc_ring {
	__u32 id;
	__u8 state;
};

struct rc_cap {
	__u32 id;
	__u8 state;
	__u8 verified;
};

struct rc_msg {
	__u32 ring;
	__u8 kind;
	__u64 ts_ns;
};

/*
 * 一条差异。data/cp 分别保留数据面与控制面
 * 的观测值，CONF 时 data 即修复后应写入的状态。
 */
struct rc_diff {
	__u32 id;
	__u8 type;
	__u8 data;
	__u8 cp;
};

struct rc_plan {
	struct rc_diff *diff;
	size_t nr;
	__u8 degrade;
	__u64 retry_ns;
};

/*
 * 动作回调。返回 0 表示成功，负值表示该动作
 * 失败；调度器记录首个错误并继续执行其余动作。
 */
struct rc_ops {
	int (*ring_rec)(__u32 id);
	int (*ring_drop)(__u32 id);
	int (*ring_adopt)(__u32 id, __u8 state);
	int (*cap_check)(__u32 id);
	int (*cap_revoke)(__u32 id);
	int (*msg_send)(__u32 ring, __u64 ts_ns);
	int (*msg_drop)(__u32 ring, __u64 ts_ns);
	void (*degrade)(int why);
};

/* 报告计数：diff 按类型计，msg 按判定结果计 */
struct rc_report {
	__u32 rings_new;
	__u32 rings_miss;
	__u32 rings_conf;
	__u32 caps_verify;
	__u32 caps_revoke;
	__u32 msg_sent;
	__u32 msg_drop;
	__u32 acted;
	__u32 failed;
	__u8 degrade;
	__u64 retry_ns;
	int error;
};

struct rc_ctx {
	const struct rc_ring *state_rings;
	size_t state_rings_nr;
	const struct rc_cap *state_caps;
	size_t state_caps_nr;
	const struct rc_msg *msgs;
	size_t msgs_nr;
	const struct rc_ring *scan_rings;
	size_t scan_rings_nr;
	const struct rc_cap *scan_caps;
	size_t scan_caps_nr;
	const struct rc_ops *ops;
	__u64 (*now_ns)(void);
	struct rc_report report;
	__u8 degrade;
};

/*
 * 单次 Reconciliation 主入口。
 * 成功返回 0，回调失败返回首个负错误，
 * 输入超限返回 -E2BIG，参数缺失返回 -EINVAL。
 */
int rc_run(struct rc_ctx *ctx);

#endif /* AIRY_IPC_RC_API_H */

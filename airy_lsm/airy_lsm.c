// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_lsm.c — AirymaxOS 纯 C LSM 独立内核模块（airy_ind）
 *
 * ⚠️⚠️⚠️ 安全警告 — UAF 风险 ⚠️⚠️⚠️
 * ─────────────────────────────────────────────────────────────────
 * 本模块（airy_ind）使用直接覆写 task->security 指针的方式管理
 * 安全上下文（见 airy_ind_task_alloc 第 task->security = sec 赋值）。
 *
 * 而 kernel/security/airy/airy_lsm.c（DEFINE_LSM(airy)）使用 LSM
 * blob 机制（task->security + airy_blob_sizes.lbs_task 偏移访问）。
 *
 * 如果两个 LSM 同时加载，airy_ind 的 task_alloc 会覆写 task->security
 * 指针，导致 airy LSM 的 task_free 通过 blob 偏移读取到 airy_ind
 * 分配的 kzalloc 内存而非 blob 内存，触发 use-after-free 或 double-free。
 *
 * 禁止在生产构建中同时加载 airy 和 airy_ind。airy_ind 仅用于 [IND]
 * 教学和研究目的，生产环境必须使用 kernel/security/airy/airy_lsm.c。
 *
 * 1.0.1 计划：将 airy_ind 迁移到 LSM blob 机制（lsm_set_blob）以消除
 * 此 UAF 风险。参见 v3.5 审查报告 P0-3。
 * ─────────────────────────────────────────────────────────────────
 *
 * 职责：
 *   作为 [IND] 完全独立层的 LSM 实例，通过 DEFINE_LSM(airy_ind)
 *   注册到 Linux 安全模块框架。实现 task_alloc 钩子，为每个
 *   新建任务分配 airy_task_sec 安全上下文（[SC] lsm_types.h 定义）。
 *
 * 命名约定：
 *   - kernel/security/airy/airy_lsm.c → DEFINE_LSM(airy)    [SS] 同源层
 *   - security/airy_lsm/airy_lsm.c    → DEFINE_LSM(airy_ind) [IND] 独立层
 *   两者**禁止**重名（会导致 LSM 注册冲突）。
 *
 * 决策 F1：真实可编译实现（非桩，非 return -ENOSYS）。
 *
 * 相关文档：
 *   docs/AirymaxOS/10-architecture/07-directory-structure.md §4.3
 *   kernel/include/uapi/linux/airymax/lsm_types.h
 */

#include <linux/lsm_hooks.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/init.h>

/* [SC] 共享契约头文件（通过 -I../kernel/include/uapi/linux 引用） */
#include <airymax/lsm_types.h>
#include <airymax/error.h>

/* ─── 模块信息 ──────────────────────────────────────────────────────── */

#define AIRY_IND_LSM_NAME	"airy_ind"
#define AIRY_IND_LSM_VERSION	"0.1.1"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("SPHARX Engineering Standards Group <eng-standards@spharx.com>");
MODULE_DESCRIPTION("AirymaxOS pure-C LSM (airy_ind) — IND independent layer");
MODULE_VERSION(AIRY_IND_LSM_VERSION);

/* ─── 统计计数器 ────────────────────────────────────────────────────── */

static atomic_t airy_ind_alloc_count = ATOMIC_INIT(0);
static atomic_t airy_ind_free_count = ATOMIC_INIT(0);

/* ─── task_alloc 钩子实现 ──────────────────────────────────────────── */

/*
 * airy_ind_task_alloc - 为新建任务分配安全上下文
 *
 * @task: 新建的 task_struct
 * @clone_flags: clone() 系统调用的标志位
 *
 * 返回值：
 *   0       - 成功
 *   -ENOMEM - 内存分配失败
 *
 * 实现：
 *   1. 使用 kzalloc 分配 struct airy_task_sec（[SC] lsm_types.h 定义）
 *   2. 初始化安全上下文字段（agent_id / cap_space_root / agent_state 等）
 *   3. 将安全上下文关联到 task 的 security 字段
 *   4. 递增全局分配计数器
 *
 * 注意：本函数是真实实现，非 return -ENOSYS 桩。
 */
static int airy_ind_task_alloc(struct task_struct *task,
			       unsigned long clone_flags)
{
	struct airy_task_sec *sec;

	if (!task) {
		pr_err(AIRY_IND_LSM_NAME ": task_alloc 收到 NULL task\n");
		return -EINVAL;
	}

	/* 分配安全上下文（GFP_KERNEL 允许睡眠） */
	sec = kzalloc(sizeof(*sec), GFP_KERNEL);
	if (!sec) {
		pr_warn(AIRY_IND_LSM_NAME ": task_alloc kzalloc 失败 "
			"(pid=%d clone_flags=0x%lx)\n",
			task->pid, clone_flags);
		return -ENOMEM;
	}

	/* 初始化安全上下文字段 */
	sec->agent_id = 0;		/* 默认无 agent 绑定 */
	sec->cap_space_root = 0;	/* 默认无 capability 空间 */
	sec->agent_state = 0;		/* 初始状态：未激活 */
	sec->fault_count = 0;		/* 故障计数清零 */
	sec->sched_budget_ns = 0;	/* 默认无调度预算 */
	sec->last_heartbeat = 0;	/* 心跳时间戳清零 */
	sec->frozen_reason = 0;		/* 未被冻结 */
	sec->_reserved = 0;		/* 保留字段 */

	/* 记录 clone_flags 到 _reserved 供调试（0.1.1 阶段） */
	sec->_reserved = (uint32_t)(clone_flags & 0xFFFFFFFF);

	/* 将安全上下文关联到 task（通过 task->security） */
	/*
	 * 注意：在纯 C LSM 框架中，安全上下文通常通过
	 * lsm_blob_sizes + security 分配机制关联。
	 * 0.1.1 阶段简化为直接保存指针到 task->security，
	 * 1.0.1 将迁移到 LSM blob 机制（lsm_set_blob）。
	 */
	task->security = sec;

	atomic_inc(&airy_ind_alloc_count);

	pr_debug(AIRY_IND_LSM_NAME ": task_alloc 成功 pid=%d "
		 "clone_flags=0x%lx sec=%px\n",
		 task->pid, clone_flags, sec);

	return 0;
}

/*
 * airy_ind_task_free - 释放任务的安全上下文
 *
 * @task: 即将被销毁的 task_struct
 *
 * 实现：
 *   1. 从 task 取回安全上下文
 *   2. 清零敏感字段（防止信息泄漏）
 *   3. kfree 释放内存
 *   4. 递增全局释放计数器
 */
static void airy_ind_task_free(struct task_struct *task)
{
	struct airy_task_sec *sec;

	if (!task) {
		pr_warn(AIRY_IND_LSM_NAME ": task_free 收到 NULL task\n");
		return;
	}

	sec = (struct airy_task_sec *)task->security;
	if (!sec) {
		return;
	}

	/* 清零敏感字段（防止信息泄漏） */
	memset(sec, 0, sizeof(*sec));

	kfree(sec);
	task->security = NULL;

	atomic_inc(&airy_ind_free_count);

	pr_debug(AIRY_IND_LSM_NAME ": task_free 成功 pid=%d\n",
		 task->pid);
}

/* ─── LSM 钩子表 ────────────────────────────────────────────────────── */

static struct security_hook_list airy_ind_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(task_alloc, airy_ind_task_alloc),
	LSM_HOOK_INIT(task_free, airy_ind_task_free),
};

/* ─── 模块初始化 ────────────────────────────────────────────────────── */

/*
 * airy_ind_init - LSM 模块初始化
 *
 * 注册安全钩子到 LSM 框架。
 *
 * 返回值：
 *   0 - 成功
 *   负值 - 失败
 */
static int __init airy_ind_init(void)
{
	pr_info(AIRY_IND_LSM_NAME ": 初始化 v" AIRY_IND_LSM_VERSION "\n");
	pr_info(AIRY_IND_LSM_NAME ": [IND] 独立层 LSM 实例 "
		"(与 kernel airy [SS] 共存)\n");
	pr_info(AIRY_IND_LSM_NAME ": 钩子数=%zu "
		"(task_alloc + task_free)\n",
		ARRAY_SIZE(airy_ind_hooks));

	/* 注册安全钩子 */
	security_add_hooks(airy_ind_hooks,
			   ARRAY_SIZE(airy_ind_hooks),
			   AIRY_IND_LSM_NAME);

	pr_info(AIRY_IND_LSM_NAME ": 注册完成，"
		"等待 task_alloc 触发\n");

	return 0;
}

/* ─── LSM 注册（DEFINE_LSM） ────────────────────────────────────────── */

/*
 * DEFINE_LSM(airy_ind) — 注册到 LSM 框架
 *
 * 名字 "airy_ind" 的含义：
 *   - "airy"：AirymaxOS 安全子系统
 *   - "_ind"：[IND] 独立层实例（IRON-9 v3 四层模型）
 *
 * LSM_ORDER_MUTABLE：允许与其他 LSM 动态排序
 *
 * 注意：禁止将名字改为 "airy"（会与 kernel 子仓的内建 LSM 冲突）。
 */
DEFINE_LSM(airy_ind) = {
	.name = AIRY_IND_LSM_NAME,
	.init = airy_ind_init,
};

/* ─── 模块退出（内置 LSM 不支持卸载，仅符号导出） ─────────────────── */

/*
 * 内核模块版本信息（可通过 modinfo airy_ind.ko 查看）
 */
MODULE_INFO(integrity, "AirymaxOS IND-layer LSM — "
			"task_alloc + task_free hooks");

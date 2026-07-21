# 纯 C LSM 设计（airy_ind 独立模块）

> 本文档描述 security 子仓中纯 C LSM 独立内核模块（airy_ind）的设计。

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

License: GPL-2.0-only

---

## 1. 设计目标

提供 AirymaxOS 安全子系统的 [IND] 独立层 LSM 实例，作为 kernel 子仓
内建 `DEFINE_LSM(airy)`（[SS] 同源层）的补充。

## 2. LSM 命名约定

| 位置 | LSM 名 | IRON-9 主层 | 注册方式 |
|------|--------|-------------|---------|
| `kernel/security/airy/` | `airy` | [SS] | `DEFINE_LSM(airy)` |
| `security/airy_lsm/` | `airy_ind` | [IND] | `DEFINE_LSM(airy_ind)` |

两者**禁止**重名（会导致 LSM 注册冲突）。

## 3. 0.1.1 实现状态

### 3.1 已实现钩子

| 钩子 | 函数 | 说明 |
|------|------|------|
| `task_alloc` | `airy_ind_task_alloc()` | 分配 `struct airy_task_sec` |
| `task_free` | `airy_ind_task_free()` | 释放安全上下文 |

### 3.2 安全上下文结构（[SC] lsm_types.h）

```c
struct airy_task_sec {
    __u32   agent_id;         /* Agent 标识 */
    __u32   cap_space_root;   /* Capability 空间根 */
    __u32   agent_state;      /* Agent 生命周期状态 */
    __u32   fault_count;      /* 累计故障计数 */
    __u64   sched_budget_ns;  /* 调度预算（纳秒） */
    __u64   last_heartbeat;   /* 最后心跳时间戳 */
    __u32   frozen_reason;    /* 冻结原因码 */
    __u32   _reserved;        /* 对齐保留 */
};
```

## 4. 构建与加载

```bash
# 构建
cd security
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# 加载（需要 root）
sudo insmod airy_lsm/airy_ind.ko

# 查看
dmesg | grep airy_ind
cat /sys/kernel/security/lsm
```

## 5. 相关文档

- [07-directory-structure.md](../../../docs/AirymaxOS/10-architecture/07-directory-structure.md) §4.3 — security 子仓完整目录结构
- [07-airy-lsm-design.md](../../../docs/AirymaxOS/10-architecture/07-airy-lsm-design.md) — 纯 C LSM 设计（引用）
- [lsm_types.h](../../kernel/include/uapi/linux/airymax/lsm_types.h) — [SC] LSM 类型契约

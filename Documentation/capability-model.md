# Capability 系统设计

> 本文档描述 security 子仓中 Capability 系统的设计（41 ID + seL4 派生模型）。

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

License: GPL-2.0-only

---

## 1. 设计目标

提供 AirymaxOS 的 Capability 系统，基于 seL4 CNode 派生模型，
实现细粒度的权限管理。

## 2. 核心概念

### 2.1 Capability Slot（[SC] lsm_types.h）

```c
struct airy_cap_slot {
    __u64   badge;            /* 64-bit Capability Folding badge */
    __u32   agent_id;         /* 拥有者 Agent ID */
    __u32   flags;            /* 槽位标志 */
    __u32   randtag;          /* 防伪随机标签 */
    __u16   perms;            /* 权限位 */
    __u16   _pad;             /* 对齐 */
    __u8    _reserved[56];    /* Cache 行对齐 */
} __attribute__((aligned(64)));
```

### 2.2 Badge 64-bit 布局（[SC] ipc.h）

```
| Epoch (16 bit) | RandomTag (32 bit) | Perms (16 bit) |
|     bits 63-48 |       bits 47-16   |   bits 15-0    |
```

### 2.3 派生操作（seL4 风格）

| 操作 | 说明 |
|------|------|
| Copy | 复制 Capability（相同权限） |
| Mint | 复制并限制权限 |
| Move | 移动 Capability（源槽位清空） |
| Mutate | 修改权限 |
| Revoke | 撤销所有派生 |
| Delete | 删除 Capability |
| Rotate | 轮换 Epoch |

## 3. 0.1.1 实现状态

- ⏳ Capability 系统：1.0.1 补齐
- 0.1.1 仅提供 [SC] 类型契约（`lsm_types.h` / `security_types.h`）

## 4. 相关文档

- [07-directory-structure.md](../../../docs/AirymaxOS/10-architecture/07-directory-structure.md) §4.3 — security 子仓完整目录结构
- [lsm_types.h](../../kernel/include/uapi/linux/airymax/lsm_types.h) — [SC] LSM 类型契约
- [ipc.h](../../kernel/include/uapi/linux/airymax/ipc.h) — [SC] Badge 布局定义

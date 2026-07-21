# security 子仓文档索引

> **子仓定位**：AirymaxOS 安全子系统 —— 纯 C LSM + Capability 系统 + Cupolas 安全穹顶 + 完整性 + 密钥管理。

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

License: GPL-2.0-only

---

## 文档清单

### 已有文档

| 文档 | 说明 |
|------|------|
| [lsm-design.md](lsm-design.md) | 纯 C LSM 设计（airy_ind 独立模块） |
| [capability-model.md](capability-model.md) | Capability 系统设计（41 ID + seL4 派生） |

### 待编写文档（0.1.1 → 1.0.1）

| 文档 | 说明 | 计划版本 |
|------|------|---------|
| `cupolas.md` | Cupolas 安全穹顶（用户态 API） | 0.1.1 |
| `integrity.md` | 完整性度量与验证 | 0.1.1 |
| `keys.md` | 密钥环与 Vault backend | 0.1.1 |
| `lsm-hooks.md` | 250 钩子完整清单 | 1.0.1 |
| `capability-derive.md` | seL4 CNode 派生操作详解 | 1.0.1 |

## 相关文档

- [07-directory-structure.md](../../../docs/AirymaxOS/10-architecture/07-directory-structure.md) §4.3 — security 子仓完整目录结构
- [07-airy-lsm-design.md](../../../docs/AirymaxOS/10-architecture/07-airy-lsm-design.md) — 纯 C LSM 设计（引用）
- [lsm_types.h](../../kernel/include/uapi/linux/airymax/lsm_types.h) — [SC] LSM 类型契约
- [security_types.h](../../kernel/include/uapi/linux/airymax/security_types.h) — [SC] 安全类型契约
- 顶层 [CONTRIBUTING.md](../CONTRIBUTING.md) — security 子仓贡献指南

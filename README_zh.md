**语言:** [English](README.md) | 简体中文

# agentrt-liunx 安全态（AirymaxOS Security）

[![Version](https://img.shields.io/badge/version-0.1.1-5a6b7e)](https://atomgit.com/openairymax/security)
[![License](https://img.shields.io/badge/license-AGPL--3.0+Apache--2.0-4a90d9)](LICENSE)

> [agentrt-liunx（AirymaxOS）](https://atomgit.com/openairymax/agentrt-linux)（智能体操作系统）的安全子系统。
> 由 [agentrt-linux](https://atomgit.com/openairymax/agentrt-linux) 管理仓聚合的叶子仓之一。
> 复用并扩展 Airymax `cupolas` 模块以提供 OS 级内生安全。

---

## 概述

**agentrt-liunx 安全态（AirymaxOS Security）**（`airymaxos-security`）是 agentrt-liunx（AirymaxOS）（智能体操作系统）的安全子系统。它实现参考 seL4 的 capability 安全模型，与 Linux 安全模块（LSM）钩子及 Landlock 集成，新增机密计算支持，并内置国密算法以满足合规部署需求。

在 agentrt-liunx 0.1.1 中，本仓库为**文档体系完成**，包含设计文档、参考发行版规范及架构草案。实际的内核与 OS 开发在 1.0.1 版本进行。

### 核心技术

- **基于 capability 的安全** 参考 seL4，实现细粒度、可委托的授权
- **LSM 钩子** 与 agentrt-liunx 内核（AirymaxOS Kernel）集成，实现强制访问控制
- **Landlock** 提供非特权、进程级的文件系统沙箱
- **机密计算** 利用硬件 enclave 与加密虚拟化
- **国密算法**（SM2 / SM3 / SM4）满足合规部署需求

### 与 Airymax cupolas 的关系

agentrt-liunx 安全态（AirymaxOS Security）复用并扩展了 Airymax 运行时平台的 `cupolas` 模块。沙箱模型、内生安全策略与 capability 机制在用户态运行时（agentrt）与 OS 级安全层（agentrt-liunx（AirymaxOS））之间共享，确保架构同源、无适配层。

## 仓库结构（0.1.1（文档体系完成））

```
security/
├── README.md           # 本文件（英文）
├── README_zh.md        # 中文翻译
├── LICENSE             # AGPL-3.0 + Apache-2.0 双许可证
├── NOTICE              # 版权、商标与第三方声明
└── .gitignore
```

设计文档与参考发行版规范维护在伞仓的 `docs/AirymaxAgentOS/` 目录。

## 上下游依赖

### 上游

- **agentrt-liunx 内核（AirymaxOS Kernel）** — 提供 LSM 钩子、capability 原语与 io_uring 入口
- **Airymax cupolas** — 提供被复用并扩展的沙箱与内生安全模型
- **Euler 24.03 LTS / 26.03** — 安全与密码学标准参考发行版

### 下游

- **agentrt-liunx 服务态（AirymaxOS Services）** — 在每个守护进程上执行安全策略的服务层
- **agentrt-liunx 认知引擎（AirymaxOS Cognition）** — 在 Cupolas 沙箱内运行以隔离智能体的认知引擎

## 分支策略

本叶子仓在 **`feature/official-hubs-01`** 分支上开发。聚合管理仓 `agentrt-linux` 保持在 `main` 分支。

## 许可证

采用 **AGPL v3 + Apache 2.0** 双许可证（SPDX：`AGPL-3.0-or-later OR Apache-2.0`）。完整文本见 [LICENSE](LICENSE)。

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

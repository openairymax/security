# 贡献指南 - security 子仓（安全子系统）

> **治理依据**：[`docs/AirymaxOS/50-engineering-standards/07-maintainers-and-governance.md`](https://github.com/openairymax/docs/blob/main/AirymaxOS/50-engineering-standards/07-maintainers-and-governance.md)
> **开发流程**：[`docs/AirymaxOS/50-engineering-standards/05-development-process.md`](https://github.com/openairymax/docs/blob/main/AirymaxOS/50-engineering-standards/05-development-process.md)
> **工程哲学**：[`docs/AirymaxOS/50-engineering-standards/04-engineering-philosophy.md`](https://github.com/openairymax/docs/blob/main/AirymaxOS/50-engineering-standards/04-engineering-philosophy.md)

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

License: GPL-2.0-only

---

## 1. 子仓职责

security 子仓负责 AirymaxOS 的全部安全功能，包括：

- **纯 C LSM**（`airy_lsm/`）：`DEFINE_LSM(airy_ind)` 注册 + 250 钩子
  - **注意**：本子仓的 LSM 名为 `airy_ind`（[IND] 独立层实例），
    与 kernel 子仓内建的 `DEFINE_LSM(airy)`（[SS] 同源层）区分
- **Capability 系统**（`capability/`）：41 ID + seL4 派生模型 + `agent_caps[1024]` 静态数组
- **Cupolas 安全穹顶**（`cupolas/`）：用户态 API（ALLOW/DENY/AUDIT/COMPLAIN）
- **完整性**（`integrity/`）：度量与验证
- **密钥管理**（`keys/`）：密钥环 + Vault backend

### IRON-9 主层

- `[IND]`：全部组件均为 agent-linux 专属安全实现

## 2. 开发环境要求

- **C 标准**：C11（用户态组件）/ GNU C11（内核模块）
- **编译器**：gcc ≥ 11 或 clang ≥ 14
- **内核**：Linux 6.6+（内核模块构建）
- **内核头**：通过 `-I../kernel/include` 引用 [SC] 头文件

### [SC] 头文件引用约束（OS-IRON-014）

- [SC] 头文件**唯一物理宿主**：`../kernel/include/uapi/linux/airymax/`
- 本子仓通过 `-I` 引用，**禁止物理副本**
- Kbuild 配置：
  ```makefile
  ccflags-y += -I$(src)/../kernel/include
  ccflags-y += -I$(src)/../kernel/include/uapi/linux
  ```

## 3. 构建命令

### 3.1 内核模块（airy_lsm）

```bash
# 从子仓根目录构建（需要内核源码树或 build 目录）
cd security
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# 构建产物
#   airy_lsm/airy_ind.ko
```

### 3.2 用户态组件（cupolas / integrity / keys）

```bash
cd security
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## 4. 代码规范

### 4.1 C 代码风格

- **OS-STD-FMT-001**：Tab-8 缩进（由 `.clang-format` 强制）
- **OS-STD-FMT-002**：80 列硬限制
- **GPL-2.0-only**：所有 `.c` / `.h` 文件必须包含 `SPDX-License-Identifier: GPL-2.0-only`
- **版权头**：`Copyright (c) 2025-2026 SPHARX Ltd.`
- 提交前运行 `clang-format -i` 格式化

### 4.2 LSM 命名约定

| 位置 | LSM 名 | IRON-9 主层 | 说明 |
|------|--------|-------------|------|
| `kernel/security/airy/` | `airy` | [SS] | 内核内建 LSM |
| `security/airy_lsm/` | `airy_ind` | [IND] | 独立内核模块 LSM |

**禁止**将本子仓的 LSM 名改为 `airy`（会与 kernel 子仓冲突）。

## 5. 提交规范

### 5.1 DCO 签名（OS-IRON-007 / OS-KER-068）

所有提交必须包含 `Signed-off-by:` 行：

```bash
git commit -s
```

### 5.2 提交信息格式（OS-STD-PROD-031）

```
security: 简短描述（≤72 字符）

详细说明 what 和 why，72 字符换行。

Signed-off-by: Your Name <your.email@example.com>
```

### 5.3 子系统前缀

| 前缀 | 范围 |
|------|------|
| `security:` | security/ 子仓整体 |
| `security: airy_lsm:` | 纯 C LSM 模块 |
| `security: capability:` | Capability 系统 |
| `security: cupolas:` | Cupolas 安全穹顶 |
| `security: integrity:` | 完整性 |
| `security: keys:` | 密钥管理 |

## 6. 分支策略

- **开发分支**：`feature/official-hubs-01`
- 从 `feature/official-hubs-01` 创建 topic 分支
- PR 目标分支：`feature/official-hubs-01`

## 7. 测试要求

- **OS-STD-TEST-***：所有变更必须包含或更新测试
- 单元测试：随代码放在各组件目录
- 集成测试：在 `tests-linux/` 子仓
- LSM 钩子测试：见 `tests-linux/unit/test_lsm_hooks.c`

## 8. 审查流程

1. 向 `feature/official-hubs-01` 提交 PR
2. CI 运行：SSoT 校验 + Kbuild 构建 + sparse 检查 + 测试
3. 至少一名维护者审批
4. [SC] 变更需 L3 top maintainer 最终审批
5. Squash-merge

## 9. 报告问题

- **Bug**：在 [security issues](https://github.com/openairymax/security/issues) 提交
- **安全漏洞**：参见顶层 SECURITY.md（请勿公开报告安全漏洞）
- **设计讨论**：使用管理仓的 GitHub Discussions

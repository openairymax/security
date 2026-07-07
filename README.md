**Language:** English | [简体中文](README_zh.md)

# AirymaxOS Security

[![Version](https://img.shields.io/badge/version-0.1.1-5a6b7e)](https://atomgit.com/openairymax/security)
[![License](https://img.shields.io/badge/license-AGPL--3.0+Apache--2.0-4a90d9)](LICENSE)

> Security subsystem of [AirymaxOS](https://atomgit.com/openairymax/agentrt-linux) — the AI Agent Operating System.
> One of the leaf repositories aggregated by the [agentrt-linux](https://atomgit.com/openairymax/agentrt-linux) management repo.
> Reuses and extends the Airymax `cupolas` module for OS-level endogenous security.

---

## Overview

The **AirymaxOS Security** (`airymaxos-security`) is the security subsystem of AirymaxOS, the AI Agent Operating System. It implements capability-based security referencing seL4, integrates with the Linux Security Module (LSM) hooks and Landlock, adds confidential computing support, and embeds Chinese national cryptography (国密) algorithms for compliant deployments.

In Airymax 0.1.1, this repository is a **placeholder** containing only design documents, openEuler reference specifications, and architectural drafts. Actual kernel and OS development takes place in version 1.0.1.

### Core Technologies

- **Capability-based security** referencing seL4 for fine-grained, delegated authority
- **LSM hooks** integration with the AirymaxOS Kernel for mandatory access control
- **Landlock** for unprivileged, per-process filesystem sandboxes
- **Confidential computing** leveraging hardware enclaves and encrypted virtualization
- **Chinese national cryptography (国密)** algorithms (SM2 / SM3 / SM4) for compliant deployments

### Relationship with Airymax cupolas

The AirymaxOS Security reuses and extends the `cupolas` module from the Airymax runtime platform. The sandbox model, endogenous security policy and capability machinery are shared between the user-space runtime (agentrt) and the OS-level security layer (AirymaxOS), ensuring architectural homology with no adaptation layer.

## Repository Structure (0.1.1 Placeholder)

```
security/
├── README.md           # This file (English)
├── README_zh.md        # Chinese translation
├── LICENSE             # AGPL-3.0 + Apache-2.0 dual license
├── NOTICE              # Copyright, trademark and third-party notices
└── .gitignore
```

Design documents and openEuler reference specifications are maintained in the `docs/AirymaxAgentOS/` directory of the umbrella repository.

## Upstream & Downstream Dependencies

### Upstream

- **AirymaxOS Kernel** — provides the LSM hooks, capability primitives and io_uring entry points
- **Airymax cupolas** — provides the sandbox and endogenous security model that are reused and extended
- **openEuler 24.03 LTS / 26.03** — reference distribution for security and cryptography standards

### Downstream

- **AirymaxOS Services** — service layer that enforces the security policy on every daemon
- **AirymaxOS Cognition** — cognition engine that runs inside Cupolas sandboxes for agent isolation

## Branch Strategy

This leaf repository is developed on **`feature/official-hubs-01`**. The aggregating `agentrt-linux` management repo stays on `main`.

## License

Dual-licensed under **AGPL v3 + Apache 2.0** (SPDX: `AGPL-3.0-or-later OR Apache-2.0`). See [LICENSE](LICENSE) for the full text.

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

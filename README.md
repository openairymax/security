**Language:** English | [简体中文](README_zh.md)

# security — agentrt-linux (AirymaxOS) Security

[![Version](https://img.shields.io/badge/version-0.1.1-5a6b7e)](https://atomgit.com/openairymax/security)
[![License](https://img.shields.io/badge/license-AGPL--3.0+Apache--2.0-4a90d9)](LICENSE)

> Security subsystem of [agentrt-linux (AirymaxOS)](https://atomgit.com/openairymax/agentrt-linux) — the AI Agent Operating System.
> One of the 8 leaf repositories aggregated by the [agentrt-linux](https://atomgit.com/openairymax/agentrt-linux) management repo.
> Reuses and extends the Airymax `cupolas` module for OS-level endogenous security.

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

---

## Positioning

The **security** leaf repository is the security subsystem of agentrt-linux
(AirymaxOS). It implements capability-based security referencing seL4, integrates
with the Linux Security Module (LSM) hooks and Landlock, adds confidential
computing support, and embeds Chinese national cryptography (国密) algorithms for
compliant deployments.

## Core Responsibilities

- **Capability-based security** referencing seL4 for fine-grained, delegated authority.
- **LSM hooks** integration with the `kernel` subsystem for mandatory access control.
- **Landlock** for unprivileged, per-process filesystem sandboxes.
- **Confidential computing** leveraging hardware enclaves and encrypted virtualization.
- **Chinese national cryptography (国密)** — SM2 / SM3 / SM4 for compliant deployments.
- **`[SC]` contribution** — owns the `security_types.h` shared-contract header
  (single physical source under `kernel/include/uapi/linux/airymax/`).

## Relationship with Airymax `cupolas`

The security leaf repo reuses and extends the `cupolas` module from the Airymax
runtime platform. The sandbox model, endogenous security policy and capability
machinery are shared between the user-space runtime (`agentrt`) and the OS-level
security layer, ensuring architectural homology with no adaptation layer.

## Document & File List

```
security/
├── README.md           # This file (English)
├── README_zh.md        # Chinese translation
├── LICENSE             # AGPL-3.0 + Apache-2.0 dual license
├── NOTICE              # Copyright, trademark and third-party notices
├── .gitignore
└── .github/
    └── README.md       # GitHub automation for this leaf repo
```

Design documents and reference distribution specifications are maintained in the
`docs/AirymaxOS/` directory of the umbrella documentation repository.

## CI Status

Security changes are governed by management-repository workflows (each ≤ 2 jobs):

| Workflow | Jobs | Applies to security via |
|----------|------|--------------------------|
| `mgmt-orchestrator.yml` | `file-integrity` + `orchestrate-leaf-ci` | Verifies the `security/` submodule dir; aggregates this repo's CI status |
| `sc-dual-ci.yml` | `sc-validate` + `sc-trigger-and-await` | Guards `security_types.h` in the `[SC]` 10 core headers; triggers agentrt mirror PR on changes |
| `nightly.yml` | `nightly-test-suite` (seL4-style formal verification of security-critical paths) + `nightly-revert-or-budget` | Nightly cron |
| `release.yml` | `build-and-sign` (SBOM scan of `security/`, GPG/cosign signing keys) + `publish-release` | Release tag |

Language-level CI (C, crypto self-tests) is delegated to this leaf repository's
own `.github/workflows/`.

## Development Guide

- **Branch**: `feature/official-hubs-01` (the management repo stays on `main`).
- **DCO**: every commit must be `Signed-off-by` (`git commit -s`).
- **Commit prefix**: `security:`.
- **Code style**: C — tab-8, 80 cols (`.clang-format`); run `make format-check`.
- **`[SC]` changes**: edits to `security_types.h` require dual CI (agentrt-linux
  `sc-dual-ci.yml` + agentrt mirror PR) and L1+L3 approval per OS-IRON-014.
- **Function prefix**: `airy_*` (not legacy `airymaxos_*`).
- **Vulnerabilities**: report via [SECURITY.md](https://atomgit.com/openairymax/agentrt-linux/src/branch/main/SECURITY.md), not public issues.

## Upstream & Downstream

- **Upstream** — `kernel` (LSM hooks, capability primitives, io_uring); Airymax `cupolas`; Euler 24.03 LTS / 26.03 standards.
- **Downstream** — `services` (enforces policy on every daemon); `cognition` (runs agent logic inside Cupolas sandboxes).

## License

Dual-licensed under **AGPL v3 + Apache 2.0** (SPDX: `AGPL-3.0-or-later OR Apache-2.0`).
See [LICENSE](LICENSE) for the full text.

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

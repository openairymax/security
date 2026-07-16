# `.github/` — security Leaf Repository Automation

> GitHub automation directory for the **security** leaf repository of
> [agentrt-linux (AirymaxOS)](https://atomgit.com/openairymax/agentrt-linux).

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

---

## Positioning

This directory hosts security-specific GitHub automation. Management-level
orchestration (governance integrity, `[SC]` dual-CI for `security_types.h`,
nightly formal verification, release SBOM, SSoT validation) runs in the management
repository; this leaf repository hosts language-level CI for the C security
modules and crypto self-tests.

## Directory Contents

```
security/.github/
└── README.md    # This file
```

## Applicable Management-Repository Workflows

| Workflow | Jobs | Relevance to security |
|----------|------|------------------------|
| `mgmt-orchestrator.yml` | `file-integrity` + `orchestrate-leaf-ci` | Verifies the `security/` submodule dir exists; aggregates this repo's CI status |
| `sc-dual-ci.yml` | `sc-validate` + `sc-trigger-and-await` | Guards `security_types.h` (`[SC]` 6+2 set); creates agentrt mirror PR on changes |
| `nightly.yml` | `nightly-test-suite` + `nightly-revert-or-budget` | seL4-style formal verification of capability and LSM critical paths |
| `release.yml` | `build-and-sign` + `publish-release` | `syft security/` SBOM; release artifacts signed with GPG + cosign |

## Development Guide

- Add leaf-local workflows for crypto (SM2/SM3/SM4) self-tests, Landlock unit
  tests, and LSM hook coverage; keep each workflow ≤ 2 jobs.
- `[SC]` header `security_types.h` lives at `kernel/include/airymax/security_types.h`
  — single physical source, no duplicates (OS-IRON-014).
- Security APIs use the `airy_*` prefix.
- Vulnerability disclosures follow the management repository's `SECURITY.md`.

## License

Dual-licensed under **AGPL v3 + Apache 2.0** (SPDX: `AGPL-3.0-or-later OR Apache-2.0`).
See the repository root [LICENSE](../LICENSE) and [NOTICE](../NOTICE).

Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.

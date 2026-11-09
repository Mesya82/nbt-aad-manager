# Suggested GitHub Issue Backlog for Claude

Create issues only after the repository exists. Do not mark anything done from documentation alone. Each issue requires implementation, tests, evidence, and updated documentation.

| Priority | Issue | Depends on | Acceptance |
| --- | --- | --- | --- |
| P0 | Audit upstream asset formats, license and QNX commands | None | Evidence-backed compatibility/unknowns register; no mutation code |
| P0 | Define profile, transport and capability interfaces | Audit | Typed model and explicit unsupported/unknown states |
| P0 | Build stateful simulated QNX/SSH/USB head unit | Interfaces | Model filesystem, process state, mount, storage, reboot, failure injection |
| P0 | Implement safety invariant tests AC-01..AC-35 | Simulator | Stable tests with state assertions and pass/fail traceability |
| P1 | GitHub release discovery + immutable asset provenance | Audit | Arbitrary tag names, incomplete releases, pagination, failure tests |
| P1 | Secure ZIP and release layout validator | Release provider | Path/zip bomb/case/mismatch fuzz/property tests |
| P1 | Deterministic plan, scope and dry-run | Models | AC-01 read-only proved by zero mutations; plan revalidates device |
| P1 | Safe USB preparation | Archive validator | Never format; staging integrity, full/read-only/wrong device tests |
| P1 | Read-only SSH/QNX discovery | Interfaces | Host key validation, legacy algorithm compatibility, missing command cases |
| P1 | Snapshot manifest and integrity verification | Simulator | All touched objects backed up, hashes/modes/symlinks/absence captured |
| P1 | Journal and crash-safe reconciliation engine | Snapshot | Restart/retry/idempotency, torn/corrupt journal, double-execution cases |
| P1 | Transactional staged updater | Journal + QNX adapter | No in-use overwrite, failure checkpoints, verified cutover |
| P1 | Rollback and manual recovery diagnostics | Updater | All supported prior states restorable; unsafe ambiguity stops writes |
| P1 | Full simulator fault-injection campaign | Updater | Every external mutation failure before/after ack; persisted evidence |
| P1 | Cross-platform CI / coverage / fuzz / security | Modules | Strict release gate; no real-vehicle interaction in CI |
| P2 | Hardware validation on one explicitly identified profile | All above | Recorded parked-car pilot, declared limitations and compatibility update |
| Later | Download signed/verified snapshots to local PC | Proven transfer capability | Full restore verification from host backup, tested dropouts |
| Later | Direct SSH-only staging | Transfer interface | No USB required with same safety/rollback invariants |

## PR template expectations

Every PR touching executable code should answer:

- Which safety requirements and AC IDs are affected?
- What proof do tests offer beyond checking a mocked call?
- Does this change any possible remote filesystem/command side effect?
- What happens if SSH drops before vs after acknowledgement?
- Can the tool detect, pause and reconcile this new intermediate state?
- What data is backed up and how is restore verified?
- Which hardware claims are supported by actual evidence, rather than inferred?

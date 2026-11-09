# Suggested GitHub Issue Backlog for Claude

Create issues only after the repository exists. Do not mark anything done from documentation alone. Each issue requires implementation, tests, evidence, and updated documentation.

| Priority | Issue | Depends on | Acceptance |
| --- | --- | --- | --- |
| P0 | Audit upstream asset formats, license and QNX commands | None | Evidence-backed compatibility/unknowns register; no mutation code |
| P0 | Read-only head-unit probe + fake-device tests | Audit | `tools/probe/`: shape-allowlist guard, sandboxed no-write proof, full transcript of every remote call |
| P0 | Run probe on pilot car; import transcripts as fixtures | Probe | Two runs (AA stopped/running) reviewed; unknowns register updated |
| P0 | Define profile, transport and capability interfaces | Audit | Typed model and explicit unsupported/unknown states |
| P0 | Transcript recorder + replay transport | Interfaces | Record-before-return decorator; replay reproduces plans/refusals (AC-44) |
| P1 | Cargo workspace with sans-IO `nbt-aad-core` | Interfaces | Core has no network/process/fs side effects; CLI is a thin adapter |
| P1 | Choose embeddable SSH library | Probe evidence | Verified against recorded server algorithm proposal; legacy algorithms per profile only. *Candidate implemented: `russh` 0.65.1 (tests + OpenSSH interop); final confirmation needs the pilot head unit's KEXINIT.* |
| P0 | Native read-only probe (`nbt-aad-manager probe`) | Workspace, SSH library | Identical static plan to bash probe (CI parity test); in-process SSH fake-HU tests on Linux/Windows; real-OpenSSH interop job |
| P0 | Build stateful simulated QNX/SSH/USB head unit | Interfaces | Model filesystem, process state, mount, storage, reboot, failure injection |
| P0 | Implement safety invariant tests AC-01..AC-44 | Simulator | Stable tests with state assertions and pass/fail traceability |
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
| Later | Direct SSH-only staging | Transfer interface | No USB required with same safety/rollback invariants (prerequisite for Android A3) |
| Later | A1 shared core extraction checks | Workspace | Golden plan/refusal equivalence across adapters (AND-01) |
| Later | A2 Android read-only inspector | A1 | AND-02, AND-04, AND-07; no writes, no unlock |
| Later | A3 Android guarded manager | A2 + SSH-only staging | AND-03, AND-06, AND-08 plus all AC gates |
| Later | A4 optional unlock module | Independent protocol evidence | UNLOCK-01, UNLOCK-02; may never ship |
| P1 | R1 release-trust CI | CI | REL-01..REL-03 before first public binary; REL-04 for any APK |

## PR template expectations

Every PR touching executable code should answer:

- Which safety requirements and AC IDs are affected?
- What proof do tests offer beyond checking a mocked call?
- Does this change any possible remote filesystem/command side effect?
- What happens if SSH drops before vs after acknowledgement?
- Can the tool detect, pause and reconcile this new intermediate state?
- What data is backed up and how is restore verified?
- Which hardware claims are supported by actual evidence, rather than inferred?

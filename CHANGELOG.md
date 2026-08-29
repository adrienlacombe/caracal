# Changelog

All notable changes to this project are documented in this file.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Removed
- The direct `starknet-types-core = "=0.1.7"` dependency. It was an ARM-build
  workaround from the cairo-2.5 era and had become dead weight: caracal no
  longer uses the crate directly, and the pinned cairo v2.20.0 workspace
  itself depends on `starknet-types-core = "0.2.4"` (which builds fine on
  ARM — the v0.3.0 aarch64 release binaries prove it), so the pin only
  forced a duplicate 0.1.7 copy into the build.

## [0.3.0] - 2026-08-28

First release of this fork ([adrienlacombe/caracal](https://github.com/adrienlacombe/caracal)),
covering everything since upstream crytic/caracal 0.2.3.

### Compiler and toolchain

- Upgraded the Cairo compiler from 2.5.0 to **2.20.0**, stepping through every
  intermediate release (2.6.4, 2.7.1, 2.8.5, 2.9.4, 2.10.1, 2.11.4, 2.12.4,
  2.13.1, 2.14.0, 2.15.0, 2.16.1, 2.17.0, 2.18.0, 2.19.4, 2.20.0) with
  per-step snapshot review. All `cairo-lang-*` dependencies are pinned to the
  `v2.20.0` tag and the vendored `corelib/` matches it.
- Cairo >= 2.19 requires **rustc >= 1.94** to build.
- The corelib is now **embedded in the binary** at build time
  (`src/compilation/corelib.rs`), so the CLI needs no `--corelib` /
  `CORELIB_PATH` setup at all. Resolution order: `--corelib`, then
  `CORELIB_PATH`, then the embedded corelib (extracted once per compiler
  version under the OS temp dir).
- The bundled in-process compiler is now preferred over a local
  `starknet-compile` binary, which used to silently win whenever it was on
  PATH and (having no inlining flag) degraded analysis. `starknet-compile` is
  only a last-resort fallback when no corelib resolves, and prints a
  degraded-analysis warning.
- `starknet-types-core` stays pinned to `=0.1.7`: newer versions pull a
  `size-of` release that fails to build on ARM targets.

### Analysis quality

- **Function inlining is avoided** during compilation
  (`InliningStrategy::Avoid`): user functions survive as separate, named
  SIERRA functions, so detectors see real `FunctionCall` statements again
  instead of everything being flattened into compiler-generated
  `__wrapper__*` entrypoints. This revived `unused-arguments` (inert since
  Cairo 2.6) and restored precision across the named-call matchers; the
  raw-syscall matching paths are kept so pre-inlined SIERRA input still
  works.
- Reentrancy reads and writes are **paired by storage variable** (traced
  storage-base identity) instead of a wildcard that paired any read with any
  write, so reentrancy vs reentrancy-benign classification is now precise.
- Writes and events are **ordered against external calls** in the
  interprocedural reentrancy analysis: a call is no longer paired with
  writes/events that provably precede it. On the OpenZeppelin corpus this
  removed only provably-misordered pairs (reentrancy-benign 379 -> 300,
  reentrancy-events 337 -> 286, reentrancy unchanged at 105); every dropped
  finding was diffed against source order.
- `unused-arguments` is **scoped to user-written functions**: monomorphized
  generics, compiler-generated closure wrappers, mandated-but-unused `self`
  receivers, and empty stub bodies are skipped. OpenZeppelin corpus:
  892 -> 35 findings, with all sampled survivors true positives.
- `dead-code` no longer reports the compiler-generated
  `unsafe_new_component_state` constructors (OpenZeppelin corpus:
  12 -> 0 findings, all of them compiler plumbing).
- Finding messages are **humanized and stable across compiler bumps**:
  statements render as callee paths / libfunc names with stable occurrence
  ordinals instead of raw SIERRA text full of compiler-assigned VarIds and
  branch targets.
- Detector and printer output is **run-to-run deterministic**: fixed a real
  nondeterminism where `BasicBlock`'s `Eq` compared only the block id while
  `Hash` covered (function, id), making reentrancy-family counts drift
  between identical runs; the callgraph printer's module subgraphs are now
  sorted.

### Features

- **Cairo source locations in findings**: when caracal compiles the source
  itself (standalone files, cairo projects, in-process Scarb), findings
  carry ` (path/to/file.cairo:LINE)` — statement-level for statement-anchored
  findings, declaration-site for function-anchored ones. Paths are relative
  to the analyzed target (portable across OSes); corelib locations are
  dropped; Scarb dependency locations render as `<dep-name>/<path>`.
  Pre-built artifacts have no mapping and keep location-less messages.
- **`--format text|json|sarif`**: JSON is a flat findings array; SARIF 2.1.0
  includes a rules entry per detector (impact mapped to error/warning/note)
  and per-result locations. Stdout carries only the findings document —
  compilation progress moved to stderr.
- **`--fail-on <impact>`** with CI-grade exit codes: `1` when any finding is
  at or above the threshold, `0` otherwise, and `2` when caracal itself
  fails — so gating can tell findings from crashes.
- **`caracal.toml` config** (`--config` or discovered next to the target,
  then in the cwd): `safe_external_calls`, `detectors`/`exclude_detectors`,
  `fail_on`, `format`, `baseline`, `exclude_paths`. Unknown keys are a hard
  error; precedence is CLI > config > default per setting (detector
  selection: the CLI flags win as a group).
- **Finding baseline**: `--write-baseline` records fingerprints of current
  findings; `--baseline` suppresses matching findings from output and
  `--fail-on` counting. Fingerprints are SHA-256 over detector name +
  line/ordinal-normalized message + location files, so they survive
  unrelated edits that shift lines and compiler bumps that renumber
  occurrences. The same fingerprint is emitted as SARIF
  `partialFingerprints["caracalFingerprint/v1"]`.
- **In-process Scarb compilation**: Scarb projects are now compiled from
  SOURCES with the bundled compiler (driven by `scarb metadata`), gaining
  inlining-avoided analysis and source locations. Falls back to the
  historical pre-built-artifact path (`scarb build` +
  `target/dev/*.contract_class.json`, with a stderr NOTE) when a unit needs
  Cairo plugins beyond the builtin starknet suite (Rust proc macros), a
  target uses `build-external-contracts`, `scarb metadata` is
  missing/unparsable, no corelib resolves, or on any in-process compile
  error — never a hard failure where artifacts can still work.

### Detectors

22 detectors total in this release.

Restored (silently inert or degraded on Cairo >= 2.6/2.11 codegen, working
again on 2.20):

- `tx-origin`
- `use-after-pop-front`
- the reentrancy family: `reentrancy`, `reentrancy-benign`,
  `reentrancy-events`, `read-only-reentrancy`
- `unused-return`
- `unused-events`
- `unchecked-l1-handler-from`
- `unused-arguments` (revived by inlining-avoided compilation)
- the `safe_external_calls` allowlist (now matched via `starknet_keccak`
  selector constants instead of callee-name substrings)

New:

- `controlled-replace-class` (High/Medium): `replace_class_syscall` with a
  user-controlled class hash
- `controlled-deploy` (High/Medium): `deploy_syscall` with a
  user-controlled class hash
- `controlled-l1-message` (Medium/Medium): `send_message_to_l1_syscall` with
  a user-controlled `to_address`
- `unprotected-replace-class` (High/Low): `replace_class_syscall` reachable
  from an external entrypoint with no caller-address check
- `unchecked-transfer` (High/Medium): ERC20 `transfer`/`transfer_from`
  return value dropped
- `deploy-from-zero` (Medium/Medium): `deploy_syscall` with
  `deploy_from_zero` hardcoded true
- `block-values-for-randomness` (Medium/Low): block timestamp/number flowing
  into a hash or modulo
- `unchecked-zero-owner` (Medium/Low): constructor address parameter stored
  without a zero-check
- `privileged-write-no-event` (Low/Low): caller-gated entrypoint that writes
  storage but emits no event

Inert and documented (kept wired up rather than deleted):

- `dead-code`: the compiler drops unreachable user functions from SIERRA
  entirely, so there is nothing left to report on self-compiled Cairo 2.x
  code.
- `unused-arguments` stays inert on pre-inlined artifacts (Scarb fallback
  path without `inlining-strategy = "avoid"`, `starknet-compile` output),
  where declared parameters do not survive into SIERRA.

### Infrastructure

- **Real-world corpus regression jobs** in CI: per-detector finding counts
  (zeros included) are diffed against committed summaries for two pinned
  targets covering both Scarb paths — openzeppelin/cairo-contracts
  (artifact-fallback path, 96 contracts / 849 findings) and
  EkuboProtocol/governance (in-process path with source locations,
  5 contracts / 74 findings). Any drift, crash, zero contracts analyzed, or
  a target switching compilation path fails the job
  (`scripts/corpus.sh`, re-bless with `--bless`).
- **Compiler bump script** (`scripts/bump-cairo.sh <tag>`): retags all
  `cairo-lang-*` deps, replaces `corelib/` wholesale, rebuilds, runs tests,
  and reports per-detector snapshot drift without promoting anything.
- Printer smoke tests (both `.dot` exporters, structure + determinism) and
  unit tests for the `src/utils` message-builder/tracer API, which is now a
  public module.
- Gated end-to-end test for the in-process Scarb path
  (`tests/scarb_inprocess.rs`, behind `CARACAL_TEST_SCARB=1`).
- Release workflow modernized: current action versions, explicit rust
  target installation, single draft release assembled from all build
  artifacts, and two new prebuilt targets — `aarch64-apple-darwin` and
  `aarch64-unknown-linux-gnu` (native ARM runners, no cross-compilation).

### Upgrade notes

- **Scarb users: baselines will not match after upgrading.** Scarb projects
  that previously went through pre-built artifacts are now compiled
  in-process, so findings gain source locations — and location files are
  part of the baseline fingerprint. Re-run `--write-baseline` after
  upgrading.
- **New detectors produce new findings** on code that was previously clean.
  Triage them, or re-baseline to adopt incrementally.

## [0.2.3]

Upstream release — see
[crytic/caracal](https://github.com/crytic/caracal/releases/tag/v0.2.3).

[0.3.0]: https://github.com/adrienlacombe/caracal/releases/tag/v0.3.0
[0.2.3]: https://github.com/crytic/caracal/releases/tag/v0.2.3

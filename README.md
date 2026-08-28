# Caracal

Caracal is a static analyzer tool over the SIERRA representation for Starknet smart contracts.

> **Fork notice**: this is a fork of [crytic/caracal](https://github.com/crytic/caracal) upgraded to Cairo compiler **v2.20.0** (building it requires rustc >= 1.94). Compared to upstream it restores detectors that had gone inert on Cairo >= 2.6 codegen (the reentrancy family, `tx-origin`, `use-after-pop-front`, `unused-return`, `unused-events`, `unchecked-l1-handler-from`, `unused-arguments`, the `safe_external_calls` allowlist), adds five detectors (`controlled-replace-class`, `controlled-deploy`, `controlled-l1-message`, `unprotected-replace-class`, `unchecked-transfer`), compiles source with function inlining avoided so detectors see named user functions, pairs reentrancy reads/writes by storage variable, and emits stable human-readable finding messages.

## Features
- Detectors to detect vulnerable Cairo code
- Printers to report information
- Taint analysis
- Data flow analysis framework
- Easy to run in Scarb projects

## Installation

### Building from source
Building from source is the supported way to install this fork. You need the Rust compiler (>= 1.94) and Cargo.
Building from git:
```bash
cargo install --git https://github.com/adrienlacombe/caracal --profile release --force
```
Building from a local copy:
```bash
git clone https://github.com/adrienlacombe/caracal
cd caracal
cargo install --path . --profile release --force
```

### Upstream precompiled binaries
Upstream precompiled binaries are available on the upstream [releases page](https://github.com/crytic/caracal/releases) (v0.1.x for Cairo compiler 1.x.x, v0.2.x for Cairo compiler 2.x.x). They predate this fork's changes and do not include the restored or added detectors listed above.

## Usage
List detectors:
```bash
caracal detectors
```
List printers:
```bash
caracal printers
```
### Standalone
To use with a standalone cairo file just point caracal to the file: the bundled compiler is used with a copy of the [corelib](https://github.com/starkware-libs/cairo/tree/main/corelib) library that ships inside the caracal binary, so no extra setup is needed. To compile against a different corelib, pass its `src` directory with the `--corelib` cli option or the `CORELIB_PATH` environment variable (the cli option wins).

Note: the bundled compiler compiles with function inlining avoided, which gives the best detector results. A local `starknet-compile` binary is used only as a last-resort fallback when no corelib can be resolved (not even the built-in one, e.g. the temp directory is not writable); it has no inlining-strategy flag, so it compiles with the compiler's default (aggressive) inlining, and caracal prints a warning that inlining-sensitive detectors may miss findings (see the notes under the detectors table).  
Run detectors:
```bash
caracal detect path/file/to/analyze
```
```bash
caracal detect path/file/to/analyze --corelib path/to/corelib/src
```
Run printers:
```bash
caracal print path/file/to/analyze --printer printer_to_use --corelib path/to/corelib/src
```
### Cairo project
If you have a cairo project with multiple files and contracts you may need to specify which contracts with `--contract-path`. Compilation works as in the standalone case: the bundled compiler with its built-in corelib by default (`--corelib`/`CORELIB_PATH` to override), and the local `starknet-compile` binary only as a warned fallback. The path is the directory where `cairo_project.toml` resides.  
Run detectors:
```bash
caracal detect path/to/dir
```
```bash
caracal detect path/to/dir --contract-path token::myerc20::... token::myerc721::...
```
Run printers:
```bash
caracal print path/to/dir --printer printer_to_use
```
### Scarb
By default caracal compiles a Scarb project's **sources in-process** with its bundled compiler: it reads the project layout from `scarb metadata` (crate roots, editions, cfg, dependencies of every starknet-contract target, workspaces included) and compiles like the standalone/cairo-project flows — function inlining avoided and Cairo source locations in findings. Scarb only provides the metadata; your `[cairo]` profile settings do not affect the analysis.

Caracal falls back to analyzing the pre-built artifacts of a full `scarb build` (with a note on stderr explaining why) when in-process compilation is not feasible:
- a compilation unit uses Cairo plugins the bundled compiler cannot expand — above all Rust procedural macros (e.g. OpenZeppelin cairo-contracts v4+, snforge plugins), which require Scarb's proc-macro infrastructure;
- a starknet-contract target uses `build-external-contracts`;
- `scarb metadata` fails or its output cannot be parsed (scarb too old), or no corelib resolves for the bundled compiler;
- the in-process compilation itself errors.

On the fallback path findings carry no source locations, and analysis quality depends on how the artifacts were compiled, so add the following in Scarb.toml:
```bash
[[target.starknet-contract]]
sierra = true

[cairo]
sierra-replace-ids = true
inlining-strategy = "avoid"
```
`sierra-replace-ids` is required. `inlining-strategy = "avoid"` is strongly recommended: with Scarb's default (aggressive) inlining several detectors degrade or go inert because the named function calls they match on are inlined away (see the notes under the detectors table). Neither setting matters for the in-process path.

Then pass the path to the directory where Scarb.toml resides.
Run detectors:
```bash
caracal detect path/to/dir
```
Run printers:
```bash
caracal print path/to/dir --printer printer_to_use
```

### Machine-readable output and CI
`caracal detect` writes findings to stdout as colored text by default. `--format json` emits a flat JSON array of findings (`detector`, `impact`, `confidence`, `message`, `locations: [{file, line, col}]`), and `--format sarif` emits a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) document. Whatever the format, stdout carries only the findings document — compilation progress and warnings go to stderr — so the output can be piped or redirected directly. Location paths are relative to the analyzed target; findings are location-less when caracal analyzes pre-built artifacts (see the Limitations section).

`--fail-on <impact>` makes the exit code CI-grade: caracal exits `1` when any finding has impact at or above the threshold (`high` > `medium` > `low` > `informational`), and `0` otherwise. Without the flag the exit code is `0` whatever is found. Exit code `2` means caracal itself failed to run (e.g. a compilation error). `--fail-on` works with every format.
```bash
caracal detect path/to/dir --format sarif --fail-on medium > results.sarif
```
Upload the SARIF to GitHub code scanning to get findings as annotations on pull requests:
```yaml
- name: Run caracal
  run: caracal detect . --format sarif > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Configuration
`caracal detect` options can be set in a `caracal.toml`. It is looked up next to the analyzed target (the target's directory, or the file's directory for a single-file target), then in the current working directory; `--config <path>` overrides discovery. Every key is optional, and unknown keys are a hard error so typos don't get silently ignored.

```toml
# caracal.toml — all keys optional
safe_external_calls = ["::safe_foo"]          # mirrors --safe-external-calls
detectors = ["reentrancy", "tx-origin"]       # mirrors --detect (run only these)
# exclude_detectors = ["dead-code"]           # mirrors --exclude; mutually exclusive with `detectors`
fail_on = "high"                              # mirrors --fail-on: high|medium|low|informational
format = "sarif"                              # mirrors --format: text|json|sarif
baseline = "caracal-baseline.json"            # mirrors --baseline; relative to this file's directory
exclude_paths = ["tests/", "mocks/"]          # drop findings located under these paths
```

Precedence is CLI flag > config file > default, per setting — except detector selection, where the CLI flags (`--detect`, `--exclude`, `--exclude-*`) win as a group: passing any of them ignores both `detectors` and `exclude_detectors` from the config. Setting both `detectors` and `exclude_detectors` in the config is an error, the same mutual exclusion the CLI enforces for `--detect`/`--exclude`.

`exclude_paths` drops findings whose first location's file path (relative to the analyzed target, `/`-separated) starts with any entry — a literal prefix match, so end an entry with `/` to match a whole directory. Findings without a source location are never path-filtered.

### Baseline workflow
Real codebases produce many pre-existing findings; the baseline lets CI fail only on new ones. Fingerprints are line-independent (they survive unrelated edits that shift line numbers) and stable across compiler bumps in the common case; findings identical up to line numbers and occurrence ordinals share a fingerprint, so baselining one suppresses its duplicates too. The same fingerprint is exposed in SARIF output as `partialFingerprints["caracalFingerprint/v1"]`.

```bash
# 1. See where you stand
caracal detect .
# 2. Accept the current findings
caracal detect . --write-baseline           # writes caracal-baseline.json, exits 0
# 3. In CI: report and gate on NEW findings only
caracal detect . --baseline caracal-baseline.json --fail-on medium
```

Baselined findings are removed from the output and from `--fail-on` counting; a stderr line reports how many were suppressed. Commit the baseline file and regenerate it with `--write-baseline` whenever accepted findings are fixed or intentionally added.

## Detectors
Num | Detector | What it Detects | Impact | Confidence | Cairo | Notes
--- | --- | --- | --- | --- | --- | ---
1 | `controlled-library-call` | Library calls with a user controlled class hash | High | Medium | 1 & 2 |
2 | `unchecked-l1-handler-from` | Detect L1 handlers without from address check | High | Medium | 1 & 2 |
3 | `felt252-unsafe-arithmetic` | Detect user controlled operations with felt252 type, which is not overflow/underflow safe | Medium | Medium | 1 & 2 |
4 | `reentrancy` | Detect when a storage variable is read before an external call and written after | Medium | Medium | 1 & 2 |
5 | `read-only-reentrancy` | Detect when a view function read a storage variable written after an external call | Medium | Medium | 1 & 2 |
6 | `unused-events` | Events defined but not emitted | Medium | Medium | 1 & 2 |
7 | `unused-return` | Unused return values | Medium | Medium | 1 & 2 | note 3
8 | `unenforced-view` | Function has view decorator but modifies state | Medium | Medium | 1 | note 4
9 | `tx-origin` | Detect usage of the transaction origin address as access control | Medium | Medium | 2 |
10 | `unused-arguments` | Unused arguments | Low | Medium | 1 & 2 | note 2
11 | `reentrancy-benign` | Detect when a storage variable is written after an external call but not read before | Low | Medium | 1 & 2 |
12 | `reentrancy-events` | Detect when an event is emitted after an external call leading to out-of-order events | Low | Medium | 1 & 2 |
13 | `dead-code` | Private functions never used | Low | Medium | 1 & 2 | note 1
14 | `use-after-pop-front` | Detect use of an array or a span after removing element(s) | Low | Medium | 1 & 2 |
15 | `controlled-replace-class` | replace_class_syscall with a user controlled class hash | High | Medium | 2 |
16 | `controlled-deploy` | Deploy syscall with a user controlled class hash | High | Medium | 2 |
17 | `unchecked-transfer` | ERC20 transfer/transfer_from calls whose returned bool is ignored | High | Medium | 2 |
18 | `unprotected-replace-class` | replace_class_syscall reachable from an external function without a caller address check | High | Low | 2 |
19 | `controlled-l1-message` | send_message_to_l1_syscall with a user controlled to_address | Medium | Medium | 2 |
20 | `deploy-from-zero` | Deploy syscall with the deploy_from_zero flag enabled | Medium | Medium | 2 | note 5
21 | `block-values-for-randomness` | Block timestamp/number used as a randomness source (hashed or reduced by modulo) | Medium | Low | 2 |
22 | `unchecked-zero-owner` | Constructor storing a ContractAddress parameter without a zero-address check | Medium | Low | 2 | note 5
23 | `privileged-write-no-event` | Caller-gated external function writing storage without emitting an event | Low | Low | 2 |

The Cairo column represent the compiler version(s) for which the detector is valid.

Status notes:
1. `dead-code` is inert on Cairo >= 2.6: the compiler removes unreachable functions from the SIERRA program before caracal sees it, so there is no dead code left to detect (see the comment in `tests/detectors/dead_code.cairo`). The detector stays registered in case future compiler versions change this.
2. `unused-arguments` works when caracal compiles your source with its bundled compiler (the standalone-file, cairo-project and in-process Scarb flows). It is inert on SIERRA produced with default aggressive inlining — pre-built Scarb artifacts (the Scarb fallback path) unless the project sets `inlining-strategy = "avoid"`, and the last-resort `starknet-compile` fallback — because the user's declared parameters do not survive into that SIERRA as first-class parameters.
3. `unused-return`, `unused-arguments` and other detectors that match named function calls are inlining-sensitive: when analyzing pre-built Scarb artifacts (the Scarb fallback path), detection quality depends on how the artifact was compiled. Set `inlining-strategy = "avoid"` under `[cairo]` in Scarb.toml (see the Scarb usage section). Source analysis via the bundled compiler always uses inlining avoided.
4. `unenforced-view` targets Cairo 1 only (the v0 `#[view]` attribute era) and is not included in this fork's build — the detector was removed upstream when Cairo 2 support landed. For Cairo 1 projects use upstream v0.1.x.
5. `deploy-from-zero` and `unchecked-zero-owner` deliberately under-report when the relevant value is not statically visible: a `deploy_from_zero` flag that is not a compile-time literal is not flagged, and on pre-built artifacts (the Scarb fallback path) `unchecked-zero-owner` only sees constructors whose body survives default inlining as a named function with typed parameters (common in practice; a fully-inlined constructor is skipped).

## Printers
- `cfg`: Export the CFG of each function to a .dot file
- `callgraph`: Export function call graph to a .dot file

## How to contribute
Check the wiki on the following topics:
  * [How to write a detector](https://github.com/crytic/caracal/wiki/How-to-write-a-detector)
  * [How to write a printer](https://github.com/crytic/caracal/wiki/How-to-write-a-printer)

## Limitations
- When caracal compiles your source itself (the standalone-file, cairo-project and in-process Scarb flows with the bundled compiler), findings carry Cairo source locations rendered as ` (path/to/file.cairo:LINE)` — the path is relative to the analyzed target. For a Scarb project, code from an external dependency (which lives under Scarb's cache at a machine-specific absolute path) is rendered as `<dep-name>/<path within the dependency's package>` instead; corelib locations are always dropped. Locations are not available for pre-built artifacts (the Scarb fallback path and the last-resort `starknet-compile` fallback), where findings keep the location-less format and can only reference SIERRA functions/instructions.
- When caracal compiles your source itself (the standalone-file, cairo-project and in-process Scarb flows with the bundled compiler), it compiles with function inlining avoided, so user functions survive as separate, named SIERRA functions and the historical "inlined functions are not handled correctly" limitation no longer applies there. Only `#[inline(always)]` functions are still inlined. The limitation remains for pre-built SIERRA compiled with the compiler's default aggressive inlining — Scarb artifacts without `inlining-strategy = "avoid"` (the Scarb fallback path), and the last-resort `starknet-compile` fallback — where detectors that reason across calls can miss inlined code.
- Because analysis compiles with inlining avoided, the analyzed SIERRA differs from the SIERRA you deploy with default inlining: findings describe your source's semantics, not the deployed program's statement layout.

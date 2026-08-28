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
If you have a project that uses Scarb you need to add the following in Scarb.toml:
```bash
[[target.starknet-contract]]
sierra = true

[cairo]
sierra-replace-ids = true
inlining-strategy = "avoid"
```
`sierra-replace-ids` is required. `inlining-strategy = "avoid"` is strongly recommended: caracal analyzes the pre-built artifacts Scarb produces, and with Scarb's default (aggressive) inlining several detectors degrade or go inert because the named function calls they match on are inlined away (see the notes under the detectors table).

Then pass the path to the directory where Scarb.toml resides.
Run detectors:
```bash
caracal detect path/to/dir
```
Run printers:
```bash
caracal print path/to/dir --printer printer_to_use
```

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

The Cairo column represent the compiler version(s) for which the detector is valid.

Status notes:
1. `dead-code` is inert on Cairo >= 2.6: the compiler removes unreachable functions from the SIERRA program before caracal sees it, so there is no dead code left to detect (see the comment in `tests/detectors/dead_code.cairo`). The detector stays registered in case future compiler versions change this.
2. `unused-arguments` works when caracal compiles your source with its bundled compiler (the standalone-file and cairo-project flows). It is inert on SIERRA produced with default aggressive inlining — pre-built Scarb artifacts unless the project sets `inlining-strategy = "avoid"`, and the last-resort `starknet-compile` fallback — because the user's declared parameters do not survive into that SIERRA as first-class parameters.
3. `unused-return`, `unused-arguments` and other detectors that match named function calls are inlining-sensitive: when analyzing pre-built Scarb artifacts, detection quality depends on how the artifact was compiled. Set `inlining-strategy = "avoid"` under `[cairo]` in Scarb.toml (see the Scarb usage section). Source analysis via the bundled compiler always uses inlining avoided.
4. `unenforced-view` targets Cairo 1 only (the v0 `#[view]` attribute era) and is not included in this fork's build — the detector was removed upstream when Cairo 2 support landed. For Cairo 1 projects use upstream v0.1.x.

## Printers
- `cfg`: Export the CFG of each function to a .dot file
- `callgraph`: Export function call graph to a .dot file

## How to contribute
Check the wiki on the following topics:
  * [How to write a detector](https://github.com/crytic/caracal/wiki/How-to-write-a-detector)
  * [How to write a printer](https://github.com/crytic/caracal/wiki/How-to-write-a-printer)

## Limitations
- Since it's working over the SIERRA representation it's not possible to report where an error is in the source code but we can only report SIERRA instructions/what's available in a SIERRA program.
- When caracal compiles your source itself (the standalone-file and cairo-project flows with the bundled compiler), it compiles with function inlining avoided, so user functions survive as separate, named SIERRA functions and the historical "inlined functions are not handled correctly" limitation no longer applies there. Only `#[inline(always)]` functions are still inlined. The limitation remains for pre-built SIERRA compiled with the compiler's default aggressive inlining — Scarb artifacts without `inlining-strategy = "avoid"`, and the last-resort `starknet-compile` fallback — where detectors that reason across calls can miss inlined code.
- Because analysis compiles with inlining avoided, the analyzed SIERRA differs from the SIERRA you deploy with default inlining: findings describe your source's semantics, not the deployed program's statement layout.

# Caracal — agent guide

Caracal is a static analyzer for Starknet smart contracts, written in Rust. It compiles Cairo source to SIERRA and runs detectors/printers over the SIERRA representation — it never analyzes Cairo source directly. This repo is a fork of `crytic/caracal` upgraded to Cairo compiler **v2.20.0** (all `cairo-lang-*` deps are pinned to that git tag in `Cargo.toml`; the vendored `corelib/` matches it). Cairo ≥ 2.19 requires rustc ≥ 1.94.

## Build, test, lint

```bash
cargo build                 # build the CLI
cargo test                  # runs unit tests + snapshot integration tests
cargo clippy --all-targets  # CI fails on ANY warning (RUSTFLAGS="-Dwarnings")
cargo fmt --all             # rustfmt, checked in CI
```

- Tests are self-contained: the integration harness points the compiler at the vendored `corelib/src`, no environment setup needed.
- CI (`.github/workflows/ci.yml`) runs clippy with `-Dwarnings` and `cargo test` on Linux/macOS/Windows. Treat every new warning as a build break.
- Rust edition 2021. No nightly features.

## Snapshot tests (insta)

`tests/integration_tests.rs` globs every `tests/detectors/*.cairo` fixture, compiles it, runs **all** detectors, sorts the results, and asserts against a snapshot in `tests/snapshots/`.

- After changing detector behavior or adding a fixture, run `cargo test`, then review/accept snapshots with `cargo insta review` (install via `cargo install cargo-insta`), or non-interactively: `INSTA_UPDATE=always cargo test` followed by a manual diff of `tests/snapshots/`.
- Never hand-edit `.snap` files; never accept a snapshot diff you can't explain.
- Because every fixture runs every detector, adding a detector can legitimately change other fixtures' snapshots — check those diffs are expected findings, not regressions.
- The harness sets `safe_external_calls: ["::safe_foo"]` — functions matching that selector are treated as safe external calls in reentrancy fixtures.

## Real-world corpus regression (`scripts/corpus.sh`)

The synthetic fixtures can't catch a compiler bump silently killing a detector on real code, so CI's `corpus` job (ubuntu only) runs caracal over a pinned checkout of openzeppelin/cairo-contracts and diffs the per-detector finding counts (zeros included) against `tests/corpus/expected_summary.txt`. Any drift, a caracal crash, or zero contracts analyzed fails the job. Run it locally with `scripts/corpus.sh` (self-contained: downloads the pinned scarb and clones the corpus into `~/.cache/caracal-corpus`, override with `CARACAL_CORPUS_CACHE`; pass a path to reuse an existing checkout). After an *intentional* change to detector behavior, regenerate with `scripts/corpus.sh --bless`, review the summary diff finding-by-finding like a snapshot, and commit it. The OZ tag and scarb version are pinned at the top of `scripts/corpus.sh` — bump them together with compiler upgrades, then re-bless. The script patches the corpus checkout's manifests (documented in the script). Corollary: detector output must be run-to-run deterministic — `BasicBlock`'s `Eq` and `Hash` are both keyed on (function, id) for exactly this reason; don't reintroduce id-only comparisons.

## Layout

| Path | Purpose |
|---|---|
| `src/core/` | `CoreUnit`/`CompilationUnit` (analysis entry points), CFG, basic blocks, functions, SIERRA instructions |
| `src/analysis/` | Reusable analyses: dataflow framework, taint analysis, CFG traversal |
| `src/detectors/` | One file per detector + `detector.rs` (trait) + `mod.rs` (registry) |
| `src/printers/` | CFG / callgraph `.dot` exporters |
| `src/compilation/` | Cairo→SIERRA compilation glue (standalone files, cairo projects, Scarb) |
| `src/cli/` | clap-based CLI (`detect`, `print`, `detectors`, `printers` subcommands) |
| `tests/detectors/` | Cairo fixtures, one per detector, named after the detector file |
| `tests/snapshots/` | insta snapshots (committed) |
| `corelib/` | Vendored Cairo corelib (version matches the pinned compiler) — do not modify; replace wholesale when bumping the compiler |

## Adding a detector

1. Create `src/detectors/<name>.rs` implementing the `Detector` trait (`name`, `description`, `impact`, `confidence`, `run(&self, core: &CoreUnit) -> HashSet<Result>`). Kebab-case the public name (`"controlled-replace-class"`), snake_case the file.
2. Register it in `src/detectors/mod.rs`: add the `pub mod` line and a `Box::<...>::default()` entry in `get_detectors()`.
   - Build finding messages with the `statement_summary_in_function` / `statement_summary_in_named_function` helpers in `src/utils/mod.rs`, never `format!("{stmt}")` — VarIds and branch targets are compiler-assigned and churn on every compiler bump.
3. Add a fixture `tests/detectors/<name>.cairo` with both vulnerable and safe variants, run `cargo test`, and accept the new snapshot.
4. Add a row to the detectors table in `README.md`.
5. Detectors typically walk `core.get_compilation_units()` → functions → SIERRA statements, matching on `CoreConcreteLibfunc` variants, and use the taint analysis in `src/analysis/taint.rs` to decide whether inputs are user-controlled. Read a sibling detector (e.g. `controlled_library_call.rs` / `controlled_replace_class.rs`) before writing a new one.

## Constraints and gotchas

- **SIERRA-level only**: findings can't point at Cairo source locations, only at SIERRA functions/instructions. Don't promise source line numbers in messages.
- **Inlining**: since commit `329fb95` caracal compiles source with `InliningStrategy::Avoid` (set in `src/compilation/{standard,cairo_project}.rs`), so user functions survive as separate, named SIERRA functions and detectors see real `FunctionCall` statements. The historical "inlined functions are not handled correctly" caveat now applies only to pre-inlined SIERRA input: Scarb artifacts built without `inlining-strategy = "avoid"` in `[cairo]`, and the local `starknet-compile` shell-out (no inlining flag). Keep the raw-syscall matching paths in detectors — they are what still works on that input.
- Compiler behavior changes across Cairo versions can silently neuter detectors. Precedent: `unused_arguments` went inert on Cairo ≥ 2.6 (documented in commit `61488ce`, revived by the inlining-avoid change in `329fb95` — it stays inert only on pre-inlined artifacts). `dead_code` is still inert: the compiler drops unreachable functions from SIERRA entirely. When a detector stops firing after a compiler bump, check codegen changes before assuming the detector is wrong, and document inert detectors in code comments rather than deleting them.
- Some detectors are version-gated (README "Cairo" column, 1 vs 2). This fork targets Cairo 2.x.
- `Cargo.lock` is committed (binary crate) — keep it in sync when touching `Cargo.toml`. Note the `starknet-types-core = "=0.1.7"` pin and its explanatory comment; don't bump it without checking the ARM build issue described there.
- Upgrading the Cairo compiler: run `scripts/bump-cairo.sh <tag>` — it retags every `cairo-lang-*` dep, replaces `corelib/` wholesale with the upstream corelib at that tag, rebuilds (refreshing `Cargo.lock`), runs the tests, and reports per-detector snapshot drift without promoting anything. Then follow its printed checklist: review/promote snapshots, and re-pin + re-bless the corpus job (`scripts/corpus.sh`).

## Git conventions

- `master` is the default branch; current work happens on feature branches (e.g. `upgrade-cairo`).
- Commit messages are short imperative subjects ("Add controlled-replace-class detector"), no prefixes.

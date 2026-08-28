#!/usr/bin/env bash
#
# Real-world corpus regression check.
#
# Runs caracal over pinned checkouts of real-world Starknet codebases and
# compares the per-detector finding counts against the committed summaries in
# tests/corpus/. Any drift — a detector silently dying (count drops to 0) or
# exploding, caracal crashing, a target switching Scarb compilation path, or
# zero contracts being analyzed — fails the script. This is the alarm the
# synthetic snapshot fixtures cannot sound: compiler bumps have neutered
# whole detectors before without a single test failing.
#
# Targets (each pins a repo tag and asserts the Scarb compilation path taken,
# so both of caracal's Scarb paths get real-world coverage):
#
#   oz               openzeppelin/cairo-contracts (library + mocks).
#                    Exercises the ARTIFACT FALLBACK path: OZ v4 depends on
#                    Rust proc macros (openzeppelin_macros,
#                    snforge_scarb_plugin), which the bundled compiler cannot
#                    expand. Expected: tests/corpus/expected_summary_oz.txt
#
#   ekubo-governance EkuboProtocol/governance (application-style: governor,
#                    staker, airdrop — deployed protocol, MIT). Proc-macro
#                    free, so it exercises the IN-PROCESS path, including
#                    source locations in findings. Expected:
#                    tests/corpus/expected_summary_ekubo_governance.txt
#
# Usage:
#   scripts/corpus.sh [--bless] [--target NAME] [NAME=path ...]
#
#   --bless        regenerate the expected summaries from this run (use after
#                  an INTENTIONAL detector/compiler change, and review the
#                  diff of the summaries before committing)
#   --target NAME  run a single target (repeatable); default is all
#   NAME=path      reuse an existing checkout for that target instead of the
#                  cached clone
#
# Without a path override each target is shallow-cloned into a cache
# directory (override with CARACAL_CORPUS_CACHE, default
# ~/.cache/caracal-corpus).
#
# Pins (bump these together, then re-bless):
#   - OZ_TAG:        openzeppelin/cairo-contracts release tag
#   - EKUBO_TAG:     EkuboProtocol/governance release tag
#   - SCARB_VERSION: scarb release; its bundled cairo compiler should match
#                    the cairo-lang-* pin in Cargo.toml (scarb 2.20.0 ships
#                    cairo 2.20.0)
#
# If a scarb of exactly SCARB_VERSION is already on PATH it is used;
# otherwise the pinned release tarball is downloaded into the cache dir.
# caracal's Scarb compilation paths shell out to `scarb` by name (`scarb
# metadata` in-process, `scarb build` on fallback), so the provisioned scarb
# is prepended to PATH for the caracal run. That never invokes
# `starknet-compile` (the standalone/cairo-project paths use it only as a
# last-resort fallback when no corelib resolves, and a corelib is embedded
# in the caracal binary).

set -euo pipefail

OZ_TAG="v4.0.1"
EKUBO_TAG="v2.8.0"
SCARB_VERSION="2.20.0"

ALL_TARGETS=(oz ekubo-governance)

CACHE_DIR="${CARACAL_CORPUS_CACHE:-$HOME/.cache/caracal-corpus}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"

die() {
    echo "corpus: ERROR: $*" >&2
    exit 1
}

# --------------------------------------------------------- targets metadata
# (functions, not associative arrays: macOS ships bash 3.2)
target_repo() {
    case "$1" in
        oz) echo "https://github.com/OpenZeppelin/cairo-contracts.git" ;;
        ekubo-governance) echo "https://github.com/EkuboProtocol/governance.git" ;;
        *) die "unknown target $1" ;;
    esac
}

target_tag() {
    case "$1" in
        oz) echo "$OZ_TAG" ;;
        ekubo-governance) echo "$EKUBO_TAG" ;;
        *) die "unknown target $1" ;;
    esac
}

# Directory name inside the cache (the oz name predates multi-target
# support; keep it so existing caches stay warm).
target_checkout_dir() {
    case "$1" in
        oz) echo "cairo-contracts-$OZ_TAG" ;;
        ekubo-governance) echo "ekubo-governance-$EKUBO_TAG" ;;
        *) die "unknown target $1" ;;
    esac
}

target_expected() {
    case "$1" in
        oz) echo "$REPO_ROOT/tests/corpus/expected_summary_oz.txt" ;;
        ekubo-governance) echo "$REPO_ROOT/tests/corpus/expected_summary_ekubo_governance.txt" ;;
        *) die "unknown target $1" ;;
    esac
}

# Which Scarb compilation path caracal is expected to take. Asserted per
# run: a target silently switching path (e.g. the in-process one regressing
# to pre-built artifacts, losing source locations) must fail the job.
target_scarb_path() {
    case "$1" in
        oz) echo "fallback" ;;
        ekubo-governance) echo "inprocess" ;;
        *) die "unknown target $1" ;;
    esac
}

target_summary_label() {
    case "$1" in
        oz) echo "openzeppelin/cairo-contracts $OZ_TAG" ;;
        ekubo-governance) echo "EkuboProtocol/governance $EKUBO_TAG" ;;
        *) die "unknown target $1" ;;
    esac
}

is_target() {
    local t
    for t in "${ALL_TARGETS[@]}"; do
        [[ "$t" == "$1" ]] && return 0
    done
    return 1
}

# ------------------------------------------------------------ arg parsing
BLESS=0
RUN_TARGETS=()
PATH_OVERRIDES=()  # NAME=path entries
expect_target_name=0
for arg in "$@"; do
    if [[ "$expect_target_name" -eq 1 ]]; then
        is_target "$arg" || die "unknown target: $arg (targets: ${ALL_TARGETS[*]})"
        RUN_TARGETS+=("$arg")
        expect_target_name=0
        continue
    fi
    case "$arg" in
        --bless) BLESS=1 ;;
        --target) expect_target_name=1 ;;
        --target=*)
            name="${arg#--target=}"
            is_target "$name" || die "unknown target: $name (targets: ${ALL_TARGETS[*]})"
            RUN_TARGETS+=("$name")
            ;;
        -h|--help)
            sed -n '2,56p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        -*) die "unknown flag: $arg" ;;
        *=*)
            name="${arg%%=*}"
            is_target "$name" || die "unknown target in override: $name (targets: ${ALL_TARGETS[*]})"
            [[ -n "${arg#*=}" ]] || die "empty path in override: $arg"
            PATH_OVERRIDES+=("$arg")
            ;;
        *) die "expected NAME=path for checkout overrides, got: $arg" ;;
    esac
done
[[ "$expect_target_name" -eq 0 ]] || die "--target needs a name (targets: ${ALL_TARGETS[*]})"
if [[ "${#RUN_TARGETS[@]}" -eq 0 ]]; then
    RUN_TARGETS=("${ALL_TARGETS[@]}")
fi

path_override_for() {
    local entry
    # ${arr[@]+...} keeps bash 3.2's `set -u` happy on empty arrays.
    for entry in ${PATH_OVERRIDES[@]+"${PATH_OVERRIDES[@]}"}; do
        if [[ "${entry%%=*}" == "$1" ]]; then
            echo "${entry#*=}"
            return 0
        fi
    done
    echo ""
}

mkdir -p "$CACHE_DIR"

# ---------------------------------------------------------------- scarb pin
scarb_version_of() {
    "$1" --version 2>/dev/null | head -n 1 | awk '{print $2}'
}

SCARB_BIN=""
if command -v scarb >/dev/null 2>&1 \
    && [[ "$(scarb_version_of "$(command -v scarb)")" == "$SCARB_VERSION" ]]; then
    SCARB_BIN="$(command -v scarb)"
else
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64) TRIPLE="x86_64-unknown-linux-gnu" ;;
        Linux-aarch64 | Linux-arm64) TRIPLE="aarch64-unknown-linux-gnu" ;;
        Darwin-x86_64) TRIPLE="x86_64-apple-darwin" ;;
        Darwin-arm64) TRIPLE="aarch64-apple-darwin" ;;
        *) die "unsupported platform $(uname -s)-$(uname -m); install scarb $SCARB_VERSION manually" ;;
    esac
    SCARB_DIR="$CACHE_DIR/scarb-v$SCARB_VERSION-$TRIPLE"
    SCARB_BIN="$SCARB_DIR/bin/scarb"
    if [[ ! -x "$SCARB_BIN" ]]; then
        echo "corpus: downloading scarb $SCARB_VERSION ($TRIPLE) into $CACHE_DIR"
        URL="https://github.com/software-mansion/scarb/releases/download/v$SCARB_VERSION/scarb-v$SCARB_VERSION-$TRIPLE.tar.gz"
        curl -sSfL "$URL" | tar xz -C "$CACHE_DIR"
        [[ -x "$SCARB_BIN" ]] || die "scarb download did not produce $SCARB_BIN"
    fi
fi

# caracal shells out to `scarb` by name; make sure it resolves to the pin.
PATH="$(dirname "$SCARB_BIN"):$PATH"
export PATH
FOUND_SCARB_VERSION="$(scarb_version_of scarb)"
[[ "$FOUND_SCARB_VERSION" == "$SCARB_VERSION" ]] \
    || die "scarb on PATH is $FOUND_SCARB_VERSION, expected $SCARB_VERSION"
echo "corpus: using scarb $SCARB_VERSION at $SCARB_BIN"

# ------------------------------------------------------------ build caracal
echo "corpus: building caracal (release)"
cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
CARACAL="$TARGET_DIR/release/caracal"
[[ -x "$CARACAL" ]] || die "caracal binary not found at $CARACAL"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/caracal-corpus.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

# ------------------------------------------------------------- corpus setup
# Prints the checkout path on stdout.
checkout_target() {
    local name="$1"
    local override corpus tag
    override="$(path_override_for "$name")"
    tag="$(target_tag "$name")"
    if [[ -z "$override" ]]; then
        corpus="$CACHE_DIR/$(target_checkout_dir "$name")"
        if [[ ! -d "$corpus" ]]; then
            echo "corpus: cloning $(target_repo "$name") $tag into $corpus" >&2
            git clone --quiet --depth 1 --branch "$tag" \
                "$(target_repo "$name")" "$corpus"
        fi
        local checked_out_tag
        checked_out_tag="$(git -C "$corpus" describe --tags --exact-match 2>/dev/null || echo unknown)"
        [[ "$checked_out_tag" == "$tag" ]] \
            || die "cached corpus $corpus is at '$checked_out_tag', expected $tag — delete it and re-run"
    else
        corpus="$override"
        [[ -d "$corpus" ]] || die "corpus path $corpus does not exist"
        [[ -f "$corpus/Scarb.toml" ]] || die "corpus path $corpus has no Scarb.toml"
        echo "corpus: using existing checkout $corpus" \
            "($(git -C "$corpus" describe --tags --always 2>/dev/null || echo 'not a git checkout'))" >&2
    fi
    echo "$corpus"
}

# ----------------------------------------------------- Scarb.toml patching
# Two idempotent patches, tailored to what OZ v4.0.1 ships (the
# ekubo-governance target needs none: no stale allowed-libfuncs list, and on
# the in-process path caracal itself controls inlining and replace-ids):
#
# 1. Every OZ manifest sets `allowed-libfuncs-list.name = "experimental"`,
#    a list cairo >= 2.20 no longer knows ("No libfunc list named
#    'experimental' is known"). Libfunc gating is irrelevant for a static
#    analysis corpus, so it is replaced with `allowed-libfuncs = false`.
#
# 2. The root `[profile.dev.cairo]` must carry `sierra-replace-ids = true`
#    (scarb's dev default, pinned explicitly — caracal needs the debug
#    names) and `inlining-strategy = "avoid"` (OZ v4.0.1 already sets it;
#    ensured here because caracal's analysis quality depends on it).
patch_manifest_libfuncs() {
    local corpus="$1" manifest="$2"
    if grep -q '^allowed-libfuncs-list\.name = "experimental"$' "$manifest"; then
        perl -pi -e 's/^allowed-libfuncs-list\.name = "experimental"$/allowed-libfuncs = false/' "$manifest"
        echo "corpus: patched allowed-libfuncs in ${manifest#"$corpus"/}"
    fi
}

patch_oz_manifests() {
    local corpus="$1"
    local manifest kv key
    patch_manifest_libfuncs "$corpus" "$corpus/Scarb.toml"
    for manifest in "$corpus"/packages/*/Scarb.toml; do
        [[ -e "$manifest" ]] || continue
        patch_manifest_libfuncs "$corpus" "$manifest"
    done

    local root_manifest="$corpus/Scarb.toml"
    if ! grep -q '^\[profile\.dev\.cairo\]$' "$root_manifest"; then
        printf '\n[profile.dev.cairo]\n' >>"$root_manifest"
        echo "corpus: appended [profile.dev.cairo] to root Scarb.toml"
    fi
    for kv in 'sierra-replace-ids = true' 'inlining-strategy = "avoid"'; do
        key="${kv%% =*}"
        if ! grep -q "^$key" "$root_manifest"; then
            perl -pi -e "s/^\\[profile\\.dev\\.cairo\\]\$/[profile.dev.cairo]\n$kv/" "$root_manifest"
            echo "corpus: added '$kv' to [profile.dev.cairo] in root Scarb.toml"
        fi
    done
}

# --------------------------------------------------------------- run target
run_target() {
    local name="$1"
    local corpus expected scarb_path
    expected="$(target_expected "$name")"
    scarb_path="$(target_scarb_path "$name")"
    corpus="$(checkout_target "$name")"

    case "$name" in
        oz) patch_oz_manifests "$corpus" ;;
    esac

    local raw_out="$WORK_DIR/$name.out"
    local raw_err="$WORK_DIR/$name.err"
    local clean_out="$WORK_DIR/$name.clean"

    echo "corpus: [$name] running caracal detect over $corpus"
    if ! "$CARACAL" detect "$corpus" >"$raw_out" 2>"$raw_err"; then
        echo "----- caracal stdout (tail) -----" >&2
        tail -n 40 "$raw_out" >&2 || true
        echo "----- caracal stderr -----" >&2
        cat "$raw_err" >&2 || true
        die "[$name] caracal detect crashed or errored — that is a real bug, investigate"
    fi

    # Strip the ANSI color codes caracal always emits.
    sed $'s/\x1b\[[0-9;]*m//g' "$raw_out" >"$clean_out"

    # Progress/diagnostic lines go to stderr (stdout is reserved for
    # findings, so `--format json|sarif` can own it).
    grep -q '^Compiling with Scarb\. Found Scarb\.toml\.$' "$raw_err" \
        || die "[$name] caracal did not take the Scarb compilation path — stderr starts with: $(head -n 1 "$raw_err")"

    # Assert which Scarb compilation path was taken (markers printed by
    # src/compilation/scarb.rs; tests/scarb_inprocess.rs checks the same).
    local analyzed
    case "$scarb_path" in
        inprocess)
            grep -q '^Compiling Scarb project sources in-process' "$raw_err" \
                || die "[$name] expected the IN-PROCESS Scarb path, but its marker is missing — a silent regression to the artifact fallback loses source-location coverage"
            grep -q 'analyzing pre-built artifacts' "$raw_err" \
                && die "[$name] expected the IN-PROCESS Scarb path, but caracal fell back to pre-built artifacts"
            analyzed="$(sed -n 's/^Compiled \([0-9][0-9]*\) contracts in-process$/\1/p' "$raw_err" | head -n 1)"
            [[ -n "$analyzed" ]] || die "[$name] missing the in-process contract count on stderr"
            ;;
        fallback)
            grep -q 'analyzing pre-built artifacts' "$raw_err" \
                || die "[$name] expected the artifact FALLBACK Scarb path, but its marker is missing"
            grep -q '^Compiling Scarb project sources in-process' "$raw_err" \
                && die "[$name] expected the artifact FALLBACK Scarb path, but the in-process path ran — re-pin the target's expectations"
            local artifacts skipped
            artifacts="$(find "$corpus/target/dev" -maxdepth 1 -name '*.contract_class.json' | wc -l | tr -d ' ')"
            skipped="$(grep -c '^Skipping analysing' "$raw_err" || true)"
            analyzed="$((artifacts - skipped))"
            ;;
        *) die "unknown scarb path $scarb_path" ;;
    esac
    [[ "$analyzed" -gt 0 ]] \
        || die "[$name] zero contracts analyzed — the classic silent-death mode"

    # A finding is printed as: `<name> Impact: <impact> Confidence: <conf>`
    # followed by the message on the next line. Count the header lines.
    local finding_re='^[a-z0-9-]+ Impact: (High|Medium|Low|Informational) Confidence: (High|Medium|Low)$'
    local names_file="$WORK_DIR/$name.finding_names"
    grep -E "$finding_re" "$clean_out" | awk '{print $1}' >"$names_file" || true
    local total
    total="$(wc -l <"$names_file" | tr -d ' ')"
    [[ "$total" -gt 0 ]] \
        || die "[$name] zero findings across the whole corpus — implausible, detectors are likely dead"

    local actual="$WORK_DIR/$name.summary.txt"
    {
        echo "# caracal corpus summary — per-detector finding counts, zero included."
        echo "# Regenerate with scripts/corpus.sh --bless after an intentional change."
        echo "# corpus: $(target_summary_label "$name")"
        echo "# scarb: $SCARB_VERSION"
        echo "contracts-analyzed: $analyzed"
        echo "total-findings: $total"
        "$CARACAL" detectors | sed $'s/\x1b\[[0-9;]*m//g' | awk -F' \\| ' '{print $1}' \
            | LC_ALL=C sort | while IFS= read -r det; do
            [[ -n "$det" ]] || continue
            count="$(grep -Fxc "$det" "$names_file" || true)"
            echo "$det: $count"
        done
    } >"$actual"

    if [[ "$BLESS" -eq 1 ]]; then
        mkdir -p "$(dirname "$expected")"
        cp "$actual" "$expected"
        echo "corpus: [$name] blessed new expected summary at ${expected#"$REPO_ROOT"/}:"
        echo
        cat "$expected"
        return 0
    fi

    [[ -f "$expected" ]] \
        || die "[$name] no expected summary at $expected — run scripts/corpus.sh --bless once and commit it"

    if diff -u "$expected" "$actual"; then
        echo "corpus: [$name] OK — $total findings over $analyzed contracts, summary matches ${expected#"$REPO_ROOT"/}"
    else
        echo >&2
        die "[$name] per-detector finding counts drifted from ${expected#"$REPO_ROOT"/} (diff above).
A detector silently dying or exploding on real code is exactly what this guards.
If the change is intentional and understood, re-bless with: scripts/corpus.sh --bless"
    fi
}

# ------------------------------------------------------------------ verdict
OVERALL=0
for name in "${RUN_TARGETS[@]}"; do
    echo
    echo "corpus: ===== target $name ====="
    # Run in a subshell with errexit restored so one target's failure does
    # not stop the others; aggregate the exit status.
    set +e
    ( set -e; run_target "$name" )
    STATUS=$?
    set -e
    if [[ "$STATUS" -ne 0 ]]; then
        echo "corpus: target $name FAILED" >&2
        OVERALL=1
    fi
done

exit "$OVERALL"

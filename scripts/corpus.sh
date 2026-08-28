#!/usr/bin/env bash
#
# Real-world corpus regression check.
#
# Runs caracal over a pinned checkout of openzeppelin/cairo-contracts and
# compares the per-detector finding counts against the committed summary in
# tests/corpus/expected_summary.txt. Any drift — a detector silently dying
# (count drops to 0) or exploding, caracal crashing, or zero contracts being
# analyzed — fails the script. This is the alarm the synthetic snapshot
# fixtures cannot sound: compiler bumps have neutered whole detectors before
# without a single test failing.
#
# Usage:
#   scripts/corpus.sh [--bless] [path-to-existing-corpus-checkout]
#
#   --bless    regenerate tests/corpus/expected_summary.txt from this run
#              (use after an INTENTIONAL detector/compiler change, and review
#              the diff of the summary before committing it)
#
# Without a path argument the corpus is shallow-cloned into a cache directory
# (override with CARACAL_CORPUS_CACHE, default ~/.cache/caracal-corpus).
#
# Pins (bump these together, then re-bless):
#   - OZ_TAG:        openzeppelin/cairo-contracts release tag
#   - SCARB_VERSION: scarb release; its bundled cairo compiler should match
#                    the cairo-lang-* pin in Cargo.toml (scarb 2.20.0 ships
#                    cairo 2.20.0)
#
# If a scarb of exactly SCARB_VERSION is already on PATH it is used;
# otherwise the pinned release tarball is downloaded into the cache dir.
# caracal's Scarb compilation path shells out to `scarb` by name, so the
# provisioned scarb is prepended to PATH for the caracal run. That path never
# invokes `starknet-compile` (the standalone/cairo-project paths use it only
# as a last-resort fallback when no corelib resolves, and a corelib is
# embedded in the caracal binary), and the script asserts that the Scarb
# path was actually taken.

set -euo pipefail

OZ_TAG="v4.0.1"
SCARB_VERSION="2.20.0"

CACHE_DIR="${CARACAL_CORPUS_CACHE:-$HOME/.cache/caracal-corpus}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED="$REPO_ROOT/tests/corpus/expected_summary.txt"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"

die() {
    echo "corpus: ERROR: $*" >&2
    exit 1
}

BLESS=0
CORPUS=""
for arg in "$@"; do
    case "$arg" in
        --bless) BLESS=1 ;;
        -h|--help)
            sed -n '2,36p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        -*) die "unknown flag: $arg" ;;
        *)
            [[ -z "$CORPUS" ]] || die "at most one corpus path argument"
            CORPUS="$arg"
            ;;
    esac
done

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

# ------------------------------------------------------------------- corpus
if [[ -z "$CORPUS" ]]; then
    CORPUS="$CACHE_DIR/cairo-contracts-$OZ_TAG"
    if [[ ! -d "$CORPUS" ]]; then
        echo "corpus: cloning openzeppelin/cairo-contracts $OZ_TAG into $CORPUS"
        git clone --quiet --depth 1 --branch "$OZ_TAG" \
            https://github.com/OpenZeppelin/cairo-contracts.git "$CORPUS"
    fi
    CHECKED_OUT_TAG="$(git -C "$CORPUS" describe --tags --exact-match 2>/dev/null || echo unknown)"
    [[ "$CHECKED_OUT_TAG" == "$OZ_TAG" ]] \
        || die "cached corpus $CORPUS is at '$CHECKED_OUT_TAG', expected $OZ_TAG — delete it and re-run"
else
    [[ -d "$CORPUS" ]] || die "corpus path $CORPUS does not exist"
    [[ -f "$CORPUS/Scarb.toml" ]] || die "corpus path $CORPUS has no Scarb.toml"
    echo "corpus: using existing checkout $CORPUS" \
        "($(git -C "$CORPUS" describe --tags --always 2>/dev/null || echo 'not a git checkout'))"
fi

# ----------------------------------------------------- Scarb.toml patching
# Two idempotent patches, tailored to what OZ v4.0.1 ships:
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
    local manifest="$1"
    if grep -q '^allowed-libfuncs-list\.name = "experimental"$' "$manifest"; then
        perl -pi -e 's/^allowed-libfuncs-list\.name = "experimental"$/allowed-libfuncs = false/' "$manifest"
        echo "corpus: patched allowed-libfuncs in ${manifest#"$CORPUS"/}"
    fi
}

patch_manifest_libfuncs "$CORPUS/Scarb.toml"
for manifest in "$CORPUS"/packages/*/Scarb.toml; do
    [[ -e "$manifest" ]] || continue
    patch_manifest_libfuncs "$manifest"
done

ROOT_MANIFEST="$CORPUS/Scarb.toml"
if ! grep -q '^\[profile\.dev\.cairo\]$' "$ROOT_MANIFEST"; then
    printf '\n[profile.dev.cairo]\n' >>"$ROOT_MANIFEST"
    echo "corpus: appended [profile.dev.cairo] to root Scarb.toml"
fi
for kv in 'sierra-replace-ids = true' 'inlining-strategy = "avoid"'; do
    key="${kv%% =*}"
    if ! grep -q "^$key" "$ROOT_MANIFEST"; then
        perl -pi -e "s/^\\[profile\\.dev\\.cairo\\]\$/[profile.dev.cairo]\n$kv/" "$ROOT_MANIFEST"
        echo "corpus: added '$kv' to [profile.dev.cairo] in root Scarb.toml"
    fi
done

# ------------------------------------------------------------ build caracal
echo "corpus: building caracal (release)"
cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
CARACAL="$TARGET_DIR/release/caracal"
[[ -x "$CARACAL" ]] || die "caracal binary not found at $CARACAL"

# -------------------------------------------------------------- run detect
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/caracal-corpus.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
RAW_OUT="$WORK_DIR/detect.out"
RAW_ERR="$WORK_DIR/detect.err"
CLEAN_OUT="$WORK_DIR/detect.clean"

echo "corpus: running caracal detect over $CORPUS (scarb builds the workspace first — takes a few minutes)"
if ! "$CARACAL" detect "$CORPUS" >"$RAW_OUT" 2>"$RAW_ERR"; then
    echo "----- caracal stdout (tail) -----" >&2
    tail -n 40 "$RAW_OUT" >&2 || true
    echo "----- caracal stderr -----" >&2
    cat "$RAW_ERR" >&2 || true
    die "caracal detect crashed or errored on the corpus — that is a real bug, investigate"
fi

# Strip the ANSI color codes caracal always emits.
sed $'s/\x1b\[[0-9;]*m//g' "$RAW_OUT" >"$CLEAN_OUT"

# Progress/diagnostic lines go to stderr (stdout is reserved for findings,
# so `--format json|sarif` can own it).
grep -q '^Compiling with Scarb\. Found Scarb\.toml\.$' "$RAW_ERR" \
    || die "caracal did not take the Scarb compilation path — stderr starts with: $(head -n 1 "$RAW_ERR")"

# --------------------------------------------------------------- summarize
ARTIFACTS="$(find "$CORPUS/target/dev" -maxdepth 1 -name '*.contract_class.json' | wc -l | tr -d ' ')"
SKIPPED="$(grep -c '^Skipping analysing' "$RAW_ERR" || true)"
ANALYZED="$((ARTIFACTS - SKIPPED))"
[[ "$ANALYZED" -gt 0 ]] \
    || die "zero contracts analyzed (artifacts: $ARTIFACTS, skipped: $SKIPPED) — the classic silent-death mode"

# A finding is printed as: `<name> Impact: <impact> Confidence: <confidence>`
# followed by the message on the next line. Count the header lines.
FINDING_RE='^[a-z0-9-]+ Impact: (High|Medium|Low|Informational) Confidence: (High|Medium|Low)$'
NAMES_FILE="$WORK_DIR/finding_names"
grep -E "$FINDING_RE" "$CLEAN_OUT" | awk '{print $1}' >"$NAMES_FILE" || true
TOTAL="$(wc -l <"$NAMES_FILE" | tr -d ' ')"
[[ "$TOTAL" -gt 0 ]] \
    || die "zero findings across the whole corpus — implausible for OZ, detectors are likely dead"

ACTUAL="$WORK_DIR/summary.txt"
{
    echo "# caracal corpus summary — per-detector finding counts, zero included."
    echo "# Regenerate with scripts/corpus.sh --bless after an intentional change."
    echo "# corpus: openzeppelin/cairo-contracts $OZ_TAG"
    echo "# scarb: $SCARB_VERSION"
    echo "contracts-analyzed: $ANALYZED"
    echo "total-findings: $TOTAL"
    "$CARACAL" detectors | sed $'s/\x1b\[[0-9;]*m//g' | awk -F' \\| ' '{print $1}' \
        | LC_ALL=C sort | while IFS= read -r det; do
        [[ -n "$det" ]] || continue
        count="$(grep -Fxc "$det" "$NAMES_FILE" || true)"
        echo "$det: $count"
    done
} >"$ACTUAL"

# ------------------------------------------------------------------ verdict
if [[ "$BLESS" -eq 1 ]]; then
    mkdir -p "$(dirname "$EXPECTED")"
    cp "$ACTUAL" "$EXPECTED"
    echo "corpus: blessed new expected summary at ${EXPECTED#"$REPO_ROOT"/}:"
    echo
    cat "$EXPECTED"
    exit 0
fi

[[ -f "$EXPECTED" ]] \
    || die "no expected summary at $EXPECTED — run scripts/corpus.sh --bless once and commit it"

if diff -u "$EXPECTED" "$ACTUAL"; then
    echo "corpus: OK — $TOTAL findings over $ANALYZED contracts, summary matches ${EXPECTED#"$REPO_ROOT"/}"
else
    echo >&2
    die "per-detector finding counts drifted from ${EXPECTED#"$REPO_ROOT"/} (diff above).
A detector silently dying or exploding on real code is exactly what this guards.
If the change is intentional and understood, re-bless with: scripts/corpus.sh --bless"
fi

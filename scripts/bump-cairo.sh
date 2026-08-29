#!/usr/bin/env bash
#
# Cairo compiler bump routine.
#
# Usage:
#   scripts/bump-cairo.sh <tag>        e.g. scripts/bump-cairo.sh v2.21.0
#
# Automates the mechanical part of a compiler upgrade:
#   1. validates <tag> exists upstream (starkware-libs/cairo)
#   2. retags every cairo-lang-* git dependency in Cargo.toml in one pass
#   3. replaces corelib/ wholesale with the upstream corelib at <tag>
#      and sanity-checks corelib/cairo_project.toml's version
#   4. cargo build (refreshes Cargo.lock) + cargo test, then reports
#      snapshot drift per fixture and per detector — WITHOUT promoting
#      any snapshot; reviewing and promoting stays a human job
#   5. prints the follow-up checklist (snapshot review, corpus re-bless)
#
# Re-running with the currently pinned tag is a supported no-op: the
# script completes with zero diff (useful as an idempotence check).

set -euo pipefail

CAIRO_REPO="https://github.com/starkware-libs/cairo.git"
CODELOAD_URL="https://codeload.github.com/starkware-libs/cairo/tar.gz/refs/tags"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_TOML="$REPO_ROOT/Cargo.toml"
SNAP_DIR="$REPO_ROOT/tests/snapshots"

die() {
    echo "bump: ERROR: $*" >&2
    exit 1
}

TAG="${1:-}"
if [[ -z "$TAG" || "$TAG" == "-h" || "$TAG" == "--help" ]]; then
    sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 1
fi
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-].+)?$ ]] \
    || die "'$TAG' does not look like a cairo release tag (expected e.g. v2.21.0)"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/caracal-bump.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$REPO_ROOT"

# ------------------------------------------------- 1. validate tag upstream
echo "bump: checking $TAG exists in $CAIRO_REPO"
git ls-remote --tags "$CAIRO_REPO" "refs/tags/$TAG" >"$WORK_DIR/lsremote.txt" \
    || die "git ls-remote against $CAIRO_REPO failed (network?)"
awk -v ref="refs/tags/$TAG" '$2 == ref { found = 1 } END { exit !found }' \
    "$WORK_DIR/lsremote.txt" \
    || die "tag $TAG not found upstream — check https://github.com/starkware-libs/cairo/tags"

# ------------------------------------------- 2. retag cairo-lang-* in Cargo.toml
# Derive the current tag from the file; refuse to guess if the deps disagree.
grep -E '^cairo-lang-[a-z0-9-]+ *= *\{' "$CARGO_TOML" >"$WORK_DIR/deps.txt" \
    || die "no cairo-lang-* dependencies found in Cargo.toml"
DEP_COUNT="$(wc -l <"$WORK_DIR/deps.txt" | tr -d ' ')"
grep -oE 'tag = "[^"]+"' "$WORK_DIR/deps.txt" \
    | sed -E 's/tag = "([^"]+)"/\1/' | sort -u >"$WORK_DIR/tags.txt"
TAGGED_COUNT="$(grep -cE 'tag = "[^"]+"' "$WORK_DIR/deps.txt" || true)"
[[ "$TAGGED_COUNT" == "$DEP_COUNT" ]] \
    || die "$DEP_COUNT cairo-lang-* deps but only $TAGGED_COUNT carry a tag — fix Cargo.toml by hand first"
TAG_VARIANTS="$(wc -l <"$WORK_DIR/tags.txt" | tr -d ' ')"
[[ "$TAG_VARIANTS" == "1" ]] \
    || die "cairo-lang-* deps carry mixed tags ($(tr '\n' ' ' <"$WORK_DIR/tags.txt")) — fix Cargo.toml by hand first"
CURRENT_TAG="$(cat "$WORK_DIR/tags.txt")"

if [[ "$CURRENT_TAG" == "$TAG" ]]; then
    echo "bump: Cargo.toml already pins $TAG ($DEP_COUNT cairo-lang-* deps) — no retag needed"
else
    echo "bump: retagging $DEP_COUNT cairo-lang-* deps: $CURRENT_TAG -> $TAG"
    NEW_TAG="$TAG" perl -pi -e 's/tag = "[^"]+"/tag = "$ENV{NEW_TAG}"/ if /^cairo-lang-/' "$CARGO_TOML"
fi

# Verify the rewrite: every cairo-lang-* dep now pins $TAG.
RETAGGED="$(grep -E '^cairo-lang-' "$CARGO_TOML" | grep -cF "tag = \"$TAG\"" || true)"
[[ "$RETAGGED" == "$DEP_COUNT" ]] \
    || die "retag went wrong: only $RETAGGED of $DEP_COUNT cairo-lang-* deps pin $TAG now"
# -------------------------------------------------- 3. replace corelib/ wholesale
TARBALL="$WORK_DIR/cairo-$TAG.tar.gz"
fetched=0
if command -v gh >/dev/null 2>&1; then
    echo "bump: fetching cairo $TAG tarball via gh api"
    if gh api "repos/starkware-libs/cairo/tarball/$TAG" >"$TARBALL" 2>"$WORK_DIR/gh.err"; then
        fetched=1
    else
        echo "bump: gh api failed, falling back to codeload.github.com" >&2
    fi
fi
if [[ "$fetched" == "0" ]]; then
    echo "bump: fetching cairo $TAG tarball via codeload.github.com"
    curl -sSfL "$CODELOAD_URL/$TAG" -o "$TARBALL" \
        || die "could not download the $TAG source tarball"
fi

tar -tzf "$TARBALL" >"$WORK_DIR/toc.txt" || die "downloaded tarball is not a valid tar.gz"
TOP="$(head -n 1 "$WORK_DIR/toc.txt" | cut -d/ -f1)"
[[ -n "$TOP" ]] || die "could not determine the tarball's top-level directory"
grep -q "^$TOP/corelib/" "$WORK_DIR/toc.txt" || die "tarball has no corelib/ subtree"

echo "bump: extracting corelib/ from the tarball"
tar -xzf "$TARBALL" -C "$WORK_DIR" "$TOP/corelib"
NEW_CORELIB="$WORK_DIR/$TOP/corelib"
[[ -f "$NEW_CORELIB/cairo_project.toml" ]] \
    || die "extracted corelib has no cairo_project.toml"

WANT_VERSION="${TAG#v}"
GOT_VERSION="$(grep -E '^version *= *"' "$NEW_CORELIB/cairo_project.toml" \
    | head -n 1 | sed -E 's/^version *= *"([^"]+)".*/\1/')"
[[ "$GOT_VERSION" == "$WANT_VERSION" ]] \
    || die "corelib/cairo_project.toml says version $GOT_VERSION, expected $WANT_VERSION — wrong tarball?"

echo "bump: replacing corelib/ (upstream corelib at $TAG, version $GOT_VERSION)"
rm -rf "$REPO_ROOT/corelib"
cp -R "$NEW_CORELIB" "$REPO_ROOT/corelib"

# ------------------------------------------------------------- 4. build + test
echo "bump: cargo build (this refreshes Cargo.lock for the new tag)"
BUILD_LOG="$WORK_DIR/build.log"
if ! cargo build 2>&1 | tee "$BUILD_LOG"; then
    if grep -qiE 'requires rustc|rustc [0-9][0-9.]* or newer|rustc version .* is (older|too old)' "$BUILD_LOG"; then
        echo >&2
        echo "bump: the new cairo tag raises the minimum supported rustc." >&2
        echo "bump: run 'rustup update', then re-run scripts/bump-cairo.sh $TAG." >&2
        echo "bump: (Cairo >= 2.19 already required rustc >= 1.94; new tags may require newer.)" >&2
    fi
    die "cargo build failed — see output above"
fi

# Stale pending snapshots would pollute the drift report.
find "$SNAP_DIR" -name '*.snap.new' -print >"$WORK_DIR/stale.txt"
if [[ -s "$WORK_DIR/stale.txt" ]]; then
    echo "bump: removing stale .snap.new files left over from a previous run:"
    sed 's/^/bump:   /' "$WORK_DIR/stale.txt"
    while IFS= read -r stale; do rm -f "$stale"; done <"$WORK_DIR/stale.txt"
fi

echo "bump: cargo test (insta writes tests/snapshots/*.snap.new for drifted fixtures)"
TEST_LOG="$WORK_DIR/test.log"
TEST_OK=1
cargo test 2>&1 | tee "$TEST_LOG" || TEST_OK=0

# ------------------------------------------------------- snapshot drift report
# Per-detector finding counts in a snapshot = its `name: "<detector>"` lines.
detector_counts() {
    grep -o 'name: "[^"]*"' "$1" 2>/dev/null \
        | sed 's/^name: "//; s/"$//' | sort | uniq -c \
        | awk '{ print $2, $1 }'
}

find "$SNAP_DIR" -name '*.snap.new' -print | sort >"$WORK_DIR/drifted.txt"
DRIFTED="$(wc -l <"$WORK_DIR/drifted.txt" | tr -d ' ')"

echo
echo "bump: ================= snapshot outcome ================="
if [[ "$DRIFTED" == "0" && "$TEST_OK" == "1" ]]; then
    echo "bump: tests green, no snapshot drift — nothing to review"
elif [[ "$DRIFTED" == "0" ]]; then
    die "cargo test FAILED but produced no snapshot drift — that is a real test/build failure, not snapshot churn; see the cargo test output above"
else
    echo "bump: $DRIFTED fixture(s) drifted (cargo test fails until they are reviewed):"
    while IFS= read -r new_snap; do
        old_snap="${new_snap%.new}"
        fixture="$(basename "$new_snap" .snap.new)"
        fixture="${fixture#integration_tests__detectors@}"
        echo
        echo "bump:   $fixture  (${new_snap#"$REPO_ROOT"/})"
        detector_counts "$old_snap" >"$WORK_DIR/old_counts.txt" || true
        detector_counts "$new_snap" >"$WORK_DIR/new_counts.txt" || true
        cut -d' ' -f1 "$WORK_DIR/old_counts.txt" "$WORK_DIR/new_counts.txt" \
            | sort -u >"$WORK_DIR/all_dets.txt"
        printf 'bump:     %-38s %5s %5s\n' "detector" "old" "new"
        while IFS= read -r det; do
            oc="$(awk -v d="$det" '$1 == d { print $2 }' "$WORK_DIR/old_counts.txt")"
            nc="$(awk -v d="$det" '$1 == d { print $2 }' "$WORK_DIR/new_counts.txt")"
            marker=""
            [[ "${oc:-0}" != "${nc:-0}" ]] && marker="   <-- count changed"
            printf 'bump:     %-38s %5s %5s%s\n' "$det" "${oc:-0}" "${nc:-0}" "$marker"
        done <"$WORK_DIR/all_dets.txt"
    done <"$WORK_DIR/drifted.txt"
    echo
    echo "bump: snapshots were NOT promoted. Review each diff yourself:"
    echo "bump:   diff <file>.snap <file>.snap.new   (or: cargo insta review)"
    echo "bump: finding messages are stable across compiler bumps, so drift usually"
    echo "bump: means real behavior change — except loop functions, whose names embed"
    echo "bump: statement ranges (e.g. bad_loop[136-339]) and churn benignly."
    echo "bump: promote an understood diff with: mv <file>.snap.new <file>.snap"
    echo "bump: then re-run cargo test."
fi

# ------------------------------------------------------------- 5. checklist
echo
echo "bump: ============== manual follow-up checklist =============="
echo "bump: [ ] review every tests/snapshots/*.snap.new diff and promote (see above)"
echo "bump: [ ] corpus job: in scripts/corpus.sh bump SCARB_VERSION to the scarb"
echo "bump:     release whose bundled cairo is $TAG (and the corpus tags — OZ_TAG,"
echo "bump:     EKUBO_TAG — if the projects have newer releases), run"
echo "bump:     scripts/corpus.sh --bless, and review each summary diff like a"
echo "bump:     snapshot — any detector dropping to 0 there is the 'silently"
echo "bump:     neutered detector' alarm. OZ manifests may need new"
echo "bump:     compat patches (see the allowed-libfuncs precedent in corpus.sh)."
echo "bump: [ ] cargo clippy --all-targets (CI runs it with -Dwarnings)"
echo "bump: [ ] update the version references in AGENTS.md if the rustc floor moved"
echo "bump: [ ] commit Cargo.toml, Cargo.lock, corelib/, snapshots and the corpus"
echo "bump:     summaries together ('Upgrade to cairo $TAG')"
echo
if [[ "$CURRENT_TAG" == "$TAG" ]]; then
    echo "bump: done — re-run with the already-pinned tag $TAG (expected zero diff)"
else
    echo "bump: done — $CURRENT_TAG -> $TAG"
fi

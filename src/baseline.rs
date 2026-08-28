//! Finding baseline: accept a codebase's current findings, fail only on new
//! ones.
//!
//! `caracal detect --write-baseline` records the fingerprint of every current
//! finding in a JSON file; later runs with `--baseline <file>` (or the
//! `baseline` config key) suppress findings whose fingerprint appears in it,
//! both from the output and from `--fail-on` counting. This is the adoption
//! path for existing codebases with hundreds of pre-existing findings.

use crate::detectors::detector::Result as DetectorResult;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;

/// Default baseline path when `--write-baseline` is used without `--baseline`
/// or a config `baseline` key.
pub const DEFAULT_BASELINE_FILE: &str = "caracal-baseline.json";

/// On-disk format version. Bump when the fingerprint composition changes so
/// stale baselines fail loudly instead of silently suppressing nothing.
const BASELINE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct BaselineFile {
    version: u32,
    /// Sorted, deduplicated fingerprints — stable diffs when the baseline is
    /// regenerated and committed.
    fingerprints: BTreeSet<String>,
}

/// Stable fingerprint of a finding, used for baseline matching and exposed as
/// SARIF `partialFingerprints` under the key `caracalFingerprint/v1`.
///
/// Composition: SHA-256 (stable across platforms and releases, already in the
/// dependency tree) over
///   detector name + normalized message + location FILE paths.
///
/// Tradeoffs, deliberately taken:
/// - The message embeds the finding's fully-qualified function path(s) —
///   `detector::Result` has no structured function field — so the fingerprint
///   is keyed on them without per-detector message parsing. Function paths
///   are compiler-stable (unlike VarIds, which the message helpers already
///   exclude).
/// - Line numbers are NOT part of the fingerprint: `normalize_message` strips
///   the `:LINE` from every embedded ` (path/file.cairo:LINE)` location, and
///   only the `file` of each structured location is hashed. Unrelated edits
///   elsewhere in a file shift lines but keep the fingerprint.
/// - Occurrence ordinals (` (2nd occurrence)`) are stripped too: they exist
///   only to keep otherwise-identical findings distinct in a HashSet, and
///   they renumber when code is added or a compiler bump changes codegen.
/// - Consequence of both: genuinely distinct findings that are identical up
///   to lines/ordinals (e.g. two identical calls in one function, or the
///   reentrancy pairings of the same call/write summaries) SHARE a
///   fingerprint, and baselining one suppresses all of them. Accepted: the
///   collision direction is conservative for noise — it can hide a
///   duplicated pre-existing issue, never invent a new one.
/// - Renaming a function or moving a finding to another file changes the
///   fingerprint (it resurfaces as "new"). That is the usual tradeoff of
///   fingerprint-based baselines and is the safer failure mode.
pub fn fingerprint(result: &DetectorResult) -> String {
    let mut hasher = Sha256::new();
    hasher.update(result.name.as_bytes());
    hasher.update([0]);
    hasher.update(normalize_message(&result.message).as_bytes());
    for location in &result.locations {
        hasher.update([0]);
        hasher.update(location.file.as_bytes());
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Strip the line-varying parts out of a finding message:
/// - `(path/to/file.cairo:LINE)` becomes `(path/to/file.cairo)`
/// - ` (Nth occurrence)` disambiguators are removed entirely
///
/// Both patterns are produced exclusively by the message helpers in
/// `src/utils/mod.rs` (`statement_summary_in_named_function`,
/// `function_summary`), so this normalization tracks those helpers. Free-form
/// message text like "operands: 1st,2nd" does not match either pattern and is
/// left alone.
fn normalize_message(message: &str) -> String {
    strip_occurrence_ordinals(&strip_location_lines(message))
}

/// Rewrite every `.cairo:<digits>)` into `.cairo)`.
fn strip_location_lines(message: &str) -> String {
    const MARKER: &[u8] = b".cairo:";
    let bytes = message.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(MARKER) {
            let digits_start = i + MARKER.len();
            let mut j = digits_start;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > digits_start && bytes.get(j) == Some(&b')') {
                out.extend_from_slice(b".cairo");
                i = j; // resume at the ')'
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Only ASCII was removed, so the bytes are still valid UTF-8.
    String::from_utf8(out).expect("normalization removes only ASCII")
}

/// Remove every ` (<digits>st|nd|rd|th occurrence)` chunk.
fn strip_occurrence_ordinals(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b" (") {
            let digits_start = i + 2;
            let mut j = digits_start;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let suffix: &[&[u8]] = &[b"st", b"nd", b"rd", b"th"];
            if j > digits_start
                && suffix.iter().any(|s| bytes[j..].starts_with(s))
                && bytes[j + 2..].starts_with(b" occurrence)")
            {
                i = j + 2 + b" occurrence)".len();
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).expect("normalization removes only ASCII")
}

/// Write the fingerprints of `results` to `path` as pretty JSON (sorted and
/// deduplicated for stable diffs). Returns the number of fingerprints
/// written, which can be lower than `results.len()` when findings collide
/// (see [`fingerprint`]).
pub fn write(path: &Path, results: &[DetectorResult]) -> Result<usize> {
    let baseline = BaselineFile {
        version: BASELINE_VERSION,
        fingerprints: results.iter().map(fingerprint).collect(),
    };
    let json = serde_json::to_string_pretty(&baseline).expect("baseline serializes infallibly");
    std::fs::write(path, json + "\n")
        .with_context(|| format!("cannot write baseline file {}", path.display()))?;
    Ok(baseline.fingerprints.len())
}

/// Load a baseline file into a set of fingerprints.
pub fn load(path: &Path) -> Result<HashSet<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read baseline file {}", path.display()))?;
    let baseline: BaselineFile = serde_json::from_str(&content)
        .with_context(|| format!("invalid baseline file {}", path.display()))?;
    if baseline.version != BASELINE_VERSION {
        bail!(
            "baseline file {} has version {} but this caracal understands version {} — \
             regenerate it with --write-baseline",
            path.display(),
            baseline.version,
            BASELINE_VERSION
        );
    }
    Ok(baseline.fingerprints.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::source_map::SourceLocation;
    use crate::detectors::detector::{Confidence, Impact};

    fn finding(message: &str, locations: Vec<SourceLocation>) -> DetectorResult {
        DetectorResult {
            name: "reentrancy".to_string(),
            impact: Impact::Medium,
            confidence: Confidence::Medium,
            message: message.to_string(),
            locations,
        }
    }

    fn location(file: &str, line: usize) -> SourceLocation {
        SourceLocation {
            file: file.to_string(),
            line,
            col: 9,
        }
    }

    #[test]
    fn normalization_strips_location_lines_and_ordinals() {
        let message = "Reentrancy in test::Contract::__wrapper__bad\n\
             \tExternal call to test::Dispatcher::foo (1st occurrence) (src/lib.cairo:47) done in test::Contract::bad\n\
             \tStorage variable #1 written after the call by write (2nd occurrence) (src/lib.cairo:50) in test::Contract::bad.";
        assert_eq!(
            normalize_message(message),
            "Reentrancy in test::Contract::__wrapper__bad\n\
             \tExternal call to test::Dispatcher::foo (src/lib.cairo) done in test::Contract::bad\n\
             \tStorage variable #1 written after the call by write (src/lib.cairo) in test::Contract::bad."
        );
    }

    #[test]
    fn normalization_leaves_free_form_text_alone() {
        // "1st,2nd" (felt252-overflow operand lists) is not an occurrence
        // ordinal; a ".cairo:" not followed by `<digits>)` is not a location.
        let message = "uses operands: 1st,2nd, see foo.cairo: the 3rd file";
        assert_eq!(normalize_message(message), message);
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = finding(
            "Library call in test::foo (lib.cairo:12)",
            vec![location("lib.cairo", 12)],
        );
        let b = finding(
            "Library call in test::foo (lib.cairo:12)",
            vec![location("lib.cairo", 12)],
        );
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_survives_line_shifts() {
        // The same finding after unrelated edits above it: line numbers moved
        // in both the message and the structured location.
        let before = finding(
            "Library call in test::foo (lib.cairo:12)",
            vec![location("lib.cairo", 12)],
        );
        let after = finding(
            "Library call in test::foo (lib.cairo:31)",
            vec![location("lib.cairo", 31)],
        );
        assert_eq!(fingerprint(&before), fingerprint(&after));
    }

    #[test]
    fn fingerprint_survives_ordinal_renumbering() {
        let before = finding(
            "call to foo (1st occurrence) (lib.cairo:12)",
            vec![location("lib.cairo", 12)],
        );
        let after = finding(
            "call to foo (2nd occurrence) (lib.cairo:14)",
            vec![location("lib.cairo", 14)],
        );
        assert_eq!(fingerprint(&before), fingerprint(&after));
    }

    #[test]
    fn fingerprint_distinguishes_detector_file_and_function() {
        let base = finding(
            "Library call in test::foo (lib.cairo:12)",
            vec![location("lib.cairo", 12)],
        );

        let mut other_detector = finding(
            "Library call in test::foo (lib.cairo:12)",
            vec![location("lib.cairo", 12)],
        );
        other_detector.name = "controlled-library-call".to_string();
        assert_ne!(fingerprint(&base), fingerprint(&other_detector));

        let other_file = finding(
            "Library call in test::foo (other.cairo:12)",
            vec![location("other.cairo", 12)],
        );
        assert_ne!(fingerprint(&base), fingerprint(&other_file));

        let other_function = finding(
            "Library call in test::bar (lib.cairo:12)",
            vec![location("lib.cairo", 12)],
        );
        assert_ne!(fingerprint(&base), fingerprint(&other_function));
    }

    #[test]
    fn baseline_round_trip() {
        let dir =
            std::env::temp_dir().join(format!("caracal-baseline-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");

        let known = finding(
            "Library call in test::foo (lib.cairo:12)",
            vec![location("lib.cairo", 12)],
        );
        let written = write(&path, std::slice::from_ref(&known)).unwrap();
        assert_eq!(written, 1);

        let fingerprints = load(&path).unwrap();
        // The recorded finding is suppressed, a new one survives.
        assert!(fingerprints.contains(&fingerprint(&known)));
        let new = finding(
            "Library call in test::baz (lib.cairo:80)",
            vec![location("lib.cairo", 80)],
        );
        assert!(!fingerprints.contains(&fingerprint(&new)));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn baseline_rejects_unknown_version() {
        let dir =
            std::env::temp_dir().join(format!("caracal-baseline-ver-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");
        std::fs::write(&path, r#"{"version": 99, "fingerprints": []}"#).unwrap();
        let err = load(&path).unwrap_err();
        assert!(err.to_string().contains("version 99"), "unexpected: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}

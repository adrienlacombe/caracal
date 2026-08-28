//! End-to-end tests for the `caracal.toml` config file and the finding
//! baseline, both at the library level (following `output_formats.rs`) and
//! through the actual binary (`CARGO_BIN_EXE_caracal`), which is the only
//! place config discovery and CLI precedence are wired together.

use caracal::baseline;
use caracal::core::core_unit::{CoreOpts, CoreUnit};
use caracal::detectors::{detector::Result, get_detectors};
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Compile one fixture and run every detector over it, exactly like the
/// snapshot harness in `integration_tests.rs`.
fn results_for_fixture(fixture: &str) -> Vec<Result> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let opts = CoreOpts {
        target: PathBuf::from(format!("{manifest_dir}/tests/detectors/{fixture}")),
        corelib: Some(PathBuf::from(format!("{manifest_dir}/corelib/src"))),
        contract_path: None,
        safe_external_calls: Some(vec!["::safe_foo".to_string()]),
    };
    let core = CoreUnit::new(opts).unwrap();
    let mut results = get_detectors()
        .iter()
        .flat_map(|d| d.run(&core))
        .collect::<Vec<Result>>();
    results.sort();
    results
}

/// The full baseline flow at the library level: generate a baseline from a
/// fixture's findings, re-apply it, and assert every finding is suppressed
/// while a synthetic new finding survives.
#[test]
fn baseline_round_trip_on_fixture() {
    let results = results_for_fixture("controlled_library_call.cairo");
    assert!(!results.is_empty(), "fixture must produce findings");

    let dir = scratch_dir("lib-round-trip");
    let path = dir.join("baseline.json");
    baseline::write(&path, &results).unwrap();
    let known = baseline::load(&path).unwrap();

    let remaining: Vec<&Result> = results
        .iter()
        .filter(|r| !known.contains(&baseline::fingerprint(r)))
        .collect();
    assert!(
        remaining.is_empty(),
        "all baselined findings must be suppressed, {} survived",
        remaining.len()
    );

    // A finding that was not in the baseline survives.
    let mut new = results_for_fixture("tx_origin.cairo");
    new.retain(|r| !known.contains(&baseline::fingerprint(r)));
    assert!(
        !new.is_empty(),
        "findings from another fixture must not be suppressed"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Binary-level tests: config discovery and CLI/config precedence live in the
// detect command, so they are exercised through the real binary.
// ---------------------------------------------------------------------------

fn scratch_dir(label: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("caracal-it-{label}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Copy the controlled_library_call fixture (2 findings, both located in the
/// fixture file) into `dir` and return the copy's path.
fn copy_fixture(dir: &Path) -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let source = PathBuf::from(format!(
        "{manifest_dir}/tests/detectors/controlled_library_call.cairo"
    ));
    let target = dir.join("controlled_library_call.cairo");
    std::fs::copy(source, &target).unwrap();
    target
}

/// Run the caracal binary with `cwd` as working directory (controls the
/// config-discovery fallback) and return its output.
fn run_caracal(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_caracal"))
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("caracal binary runs")
}

fn stdout_json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "caracal failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout is valid JSON")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn baseline_workflow_end_to_end() {
    let dir = scratch_dir("baseline-workflow");
    let fixture = copy_fixture(&dir);
    let fixture = fixture.to_str().unwrap();

    // Before any baseline: 2 findings, and --fail-on high exits 1.
    let out = run_caracal(&dir, &["detect", fixture, "--format", "json"]);
    assert_eq!(stdout_json(&out).as_array().unwrap().len(), 2);
    let out = run_caracal(&dir, &["detect", fixture, "--fail-on", "high"]);
    assert_eq!(out.status.code(), Some(1));

    // --write-baseline without --baseline defaults to caracal-baseline.json
    // in the working directory and exits 0 even though findings exist.
    let out = run_caracal(
        &dir,
        &["detect", fixture, "--write-baseline", "--fail-on", "high"],
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(stderr_text(&out).contains("caracal-baseline.json"));
    assert!(dir.join("caracal-baseline.json").is_file());
    // Stable content: pretty JSON with sorted fingerprints.
    let written = std::fs::read_to_string(dir.join("caracal-baseline.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(parsed["version"], 1);
    assert_eq!(parsed["fingerprints"].as_array().unwrap().len(), 2);

    // Re-running with the baseline reports zero findings, says how many were
    // suppressed, and --fail-on high now exits 0.
    let out = run_caracal(
        &dir,
        &[
            "detect",
            fixture,
            "--format",
            "json",
            "--baseline",
            "caracal-baseline.json",
            "--fail-on",
            "high",
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout_json(&out).as_array().unwrap().len(), 0);
    assert!(
        stderr_text(&out).contains("2 pre-existing findings suppressed by baseline"),
        "stderr: {}",
        stderr_text(&out)
    );

    // Insert a new vulnerable function at the TOP of the contract: existing
    // findings shift lines (and must stay suppressed), the new one surfaces.
    let source = std::fs::read_to_string(fixture).unwrap();
    let source = source.replace(
        "    struct Storage {}\n",
        "    struct Storage {}\n\n    #[external(v0)]\n    fn bad_new(ref self: ContractState, class_hash: ClassHash) -> u128 {\n       IAnotherContractLibraryDispatcher { class_hash: class_hash }.foo(2_u128)\n    }\n",
    );
    std::fs::write(fixture, source).unwrap();

    let out = run_caracal(
        &dir,
        &[
            "detect",
            fixture,
            "--format",
            "json",
            "--baseline",
            "caracal-baseline.json",
        ],
    );
    let findings = stdout_json(&out);
    let findings = findings.as_array().unwrap();
    assert_eq!(
        findings.len(),
        1,
        "only the new finding must survive: {findings:?}"
    );
    assert!(findings[0]["message"].as_str().unwrap().contains("bad_new"));
    assert!(stderr_text(&out).contains("2 pre-existing findings suppressed by baseline"));

    // A missing baseline file is a warning, not an error, and suppresses
    // nothing.
    let out = run_caracal(
        &dir,
        &[
            "detect",
            fixture,
            "--format",
            "json",
            "--baseline",
            "no-such-file.json",
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout_json(&out).as_array().unwrap().len(), 3);
    assert!(stderr_text(&out).contains("not found; no findings suppressed"));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn config_discovery_and_cli_precedence() {
    let dir = scratch_dir("config-discovery");
    let fixture = copy_fixture(&dir);
    let fixture = fixture.to_str().unwrap();

    // caracal.toml next to the target is discovered and applied.
    std::fs::write(
        dir.join("caracal.toml"),
        "exclude_detectors = [\"controlled-library-call\"]\nformat = \"json\"\n",
    )
    .unwrap();
    let out = run_caracal(&dir, &["detect", fixture]);
    assert!(stderr_text(&out).contains("Using configuration from"));
    // The config's format=json applies, and its exclude removes both findings.
    assert_eq!(stdout_json(&out).as_array().unwrap().len(), 0);

    // A CLI selection flag overrides the config's detector lists as a group.
    let out = run_caracal(
        &dir,
        &["detect", fixture, "--detect", "controlled-library-call"],
    );
    assert_eq!(stdout_json(&out).as_array().unwrap().len(), 2);

    // --config wins over discovery.
    std::fs::write(dir.join("other.toml"), "format = \"json\"\n").unwrap();
    let out = run_caracal(&dir, &["detect", fixture, "--config", "other.toml"]);
    assert_eq!(stdout_json(&out).as_array().unwrap().len(), 2);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn config_exclude_paths_drops_located_findings() {
    let dir = scratch_dir("config-exclude-paths");
    let fixture = copy_fixture(&dir);
    let fixture = fixture.to_str().unwrap();

    // Both fixture findings' first location file is
    // `controlled_library_call.cairo` (relative to the target); a matching
    // path prefix drops them.
    std::fs::write(
        dir.join("caracal.toml"),
        "exclude_paths = [\"controlled_\"]\nformat = \"json\"\ndetectors = [\"controlled-library-call\"]\n",
    )
    .unwrap();
    let out = run_caracal(&dir, &["detect", fixture]);
    assert_eq!(stdout_json(&out).as_array().unwrap().len(), 0);

    // A non-matching prefix keeps them.
    std::fs::write(
        dir.join("caracal.toml"),
        "exclude_paths = [\"tests/\"]\nformat = \"json\"\ndetectors = [\"controlled-library-call\"]\n",
    )
    .unwrap();
    let out = run_caracal(&dir, &["detect", fixture]);
    assert_eq!(stdout_json(&out).as_array().unwrap().len(), 2);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn config_errors_are_fatal() {
    let dir = scratch_dir("config-errors");
    let fixture = copy_fixture(&dir);
    let fixture = fixture.to_str().unwrap();

    // Unknown key (typo protection): hard error, exit code 2.
    std::fs::write(dir.join("caracal.toml"), "detectros = [\"reentrancy\"]\n").unwrap();
    let out = run_caracal(&dir, &["detect", fixture]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr_text(&out).contains("detectros"));

    // Both detector lists: the CLI's mutual-exclusion rule, as a config error.
    std::fs::write(
        dir.join("caracal.toml"),
        "detectors = [\"reentrancy\"]\nexclude_detectors = [\"tx-origin\"]\n",
    )
    .unwrap();
    let out = run_caracal(&dir, &["detect", fixture]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr_text(&out).contains("mutually exclusive"));

    // --config pointing at a missing file: hard error too (unlike discovery,
    // which just finds nothing).
    std::fs::remove_file(dir.join("caracal.toml")).unwrap();
    let out = run_caracal(&dir, &["detect", fixture, "--config", "missing.toml"]);
    assert_eq!(out.status.code(), Some(2));

    std::fs::remove_dir_all(&dir).ok();
}

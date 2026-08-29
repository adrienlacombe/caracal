//! End-to-end test for the in-process Scarb compilation path: a Scarb
//! project without proc-macro dependencies must be compiled by the bundled
//! compiler (not from pre-built artifacts) and produce findings WITH Cairo
//! source locations.
//!
//! The test shells out to `scarb metadata`, so it needs scarb on PATH — a
//! setup `cargo test` cannot assume. It is gated behind CARACAL_TEST_SCARB=1
//! and runs in CI's corpus job, which provisions the pinned scarb (see
//! .github/workflows/ci.yml).

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Copy the committed fixture package into a scratch directory, so scarb's
/// side effects (Scarb.lock) never touch the repository.
fn copy_fixture(dir: &Path) {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let fixture = PathBuf::from(format!("{manifest_dir}/tests/scarb_project"));
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::copy(fixture.join("Scarb.toml"), dir.join("Scarb.toml")).unwrap();
    std::fs::copy(
        fixture.join("src/lib.cairo"),
        dir.join("src").join("lib.cairo"),
    )
    .unwrap();
}

#[test]
fn scarb_project_compiles_in_process_with_locations() {
    if env::var("CARACAL_TEST_SCARB").as_deref() != Ok("1") {
        eprintln!("skipping: set CARACAL_TEST_SCARB=1 to run (requires scarb on PATH)");
        return;
    }

    let dir = env::temp_dir().join(format!("caracal-scarb-it-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    copy_fixture(&dir);

    let output = Command::new(env!("CARGO_BIN_EXE_caracal"))
        .args(["detect", dir.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("caracal binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "caracal failed: {stderr}\nstdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    // The in-process path was taken, not the artifact fallback.
    assert!(
        stderr.contains("Compiling Scarb project sources in-process"),
        "expected the in-process Scarb path, stderr: {stderr}"
    );
    assert!(
        !stderr.contains("analyzing pre-built artifacts"),
        "unexpected fallback to pre-built artifacts, stderr: {stderr}"
    );

    // And it produced a located finding: the fixture's unused argument,
    // pointing into the package's own source (path relative to the package
    // root, `/`-separated).
    let findings: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is valid JSON");
    let unused = findings
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["detector"] == "unused-arguments")
        .expect("the fixture's unused argument is reported");
    let location = &unused["locations"][0];
    assert_eq!(location["file"], "src/lib.cairo");
    assert!(
        location["line"].as_u64().unwrap() > 1,
        "line points into the file: {location}"
    );
    assert!(
        unused["message"]
            .as_str()
            .unwrap()
            .contains("(src/lib.cairo:"),
        "message carries the location: {}",
        unused["message"]
    );

    std::fs::remove_dir_all(&dir).ok();
}

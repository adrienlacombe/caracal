use caracal::core::core_unit::{CoreOpts, CoreUnit};
use caracal::detectors::{detector::Result, get_detectors};
use caracal::output::{render_json, render_sarif};
use std::env;
use std::path::PathBuf;

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

#[test]
fn test_json_output() {
    let results = results_for_fixture("controlled_library_call.cairo");
    let json = render_json(&results);

    // The document must be valid JSON: a flat array of findings with the
    // documented keys.
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let findings = parsed.as_array().unwrap();
    assert!(!findings.is_empty());
    for finding in findings {
        for key in ["detector", "impact", "confidence", "message", "locations"] {
            assert!(finding.get(key).is_some(), "finding is missing `{key}`");
        }
        assert!(finding["locations"].is_array());
    }
    // Locations are relative to the analyzed target, so the document is
    // machine-portable and snapshot-safe.
    insta::assert_snapshot!(json);
}

#[test]
fn test_sarif_output() {
    let results = results_for_fixture("controlled_library_call.cairo");
    let sarif = render_sarif(&results, &get_detectors());

    // The document must be valid JSON with the SARIF 2.1.0 top-level shape.
    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
    assert_eq!(
        parsed["$schema"],
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    let runs = parsed["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    let driver = &runs[0]["tool"]["driver"];
    assert_eq!(driver["name"], "caracal");
    assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
    // One rules[] entry per registered detector, findings or not.
    assert_eq!(
        driver["rules"].as_array().unwrap().len(),
        get_detectors().len()
    );
    let sarif_results = runs[0]["results"].as_array().unwrap();
    assert_eq!(sarif_results.len(), results.len());
    for result in sarif_results {
        assert!(result.get("ruleId").is_some());
        assert!(result.get("level").is_some());
        assert!(result["message"].get("text").is_some());
        // Locations, when present, must be physical locations with a
        // relative uri and a 1-based region.
        if let Some(locations) = result.get("locations") {
            for location in locations.as_array().unwrap() {
                let physical = &location["physicalLocation"];
                let uri = physical["artifactLocation"]["uri"].as_str().unwrap();
                assert!(!uri.starts_with('/'), "uri must be relative: {uri}");
                assert!(physical["region"]["startLine"].as_u64().unwrap() >= 1);
                assert!(physical["region"]["startColumn"].as_u64().unwrap() >= 1);
            }
        }
    }
    insta::assert_snapshot!(sarif);
}

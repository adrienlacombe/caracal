//! Machine-readable renderings of detector results (`--format json|sarif`).
//!
//! Both renderers write a single document to a string; the caller owns
//! stdout. Locations come from the structured `Result::locations` field —
//! paths are relative to the analyzed target and `/`-separated, so the
//! output is machine-portable.

use crate::core::source_map::SourceLocation;
use crate::detectors::detector::{Detector, Impact, Result};
use serde::Serialize;

/// One finding in the `--format json` output: a flat, stable shape meant for
/// scripting (`jq`) rather than any particular standard.
#[derive(Serialize)]
struct JsonFinding<'a> {
    detector: &'a str,
    impact: String,
    confidence: String,
    message: &'a str,
    locations: &'a [SourceLocation],
}

/// Render the findings as a JSON array of
/// `{detector, impact, confidence, message, locations: [{file, line, col}]}`.
pub fn render_json(results: &[Result]) -> String {
    let findings: Vec<JsonFinding> = results
        .iter()
        .map(|r| JsonFinding {
            detector: &r.name,
            impact: r.impact.to_string(),
            confidence: r.confidence.to_string(),
            message: &r.message,
            locations: &r.locations,
        })
        .collect();
    serde_json::to_string_pretty(&findings).expect("findings serialize infallibly")
}

// ---------------------------------------------------------------------------
// Minimal hand-rolled SARIF 2.1.0 model — only the properties caracal emits.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Sarif<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult<'a>>,
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
struct SarifDriver<'a> {
    name: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    version: &'static str,
    rules: Vec<SarifRule<'a>>,
}

#[derive(Serialize)]
struct SarifRule<'a> {
    id: &'a str,
    #[serde(rename = "shortDescription")]
    short_description: SarifText<'a>,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifConfiguration,
}

#[derive(Serialize)]
struct SarifText<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct SarifConfiguration {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifResult<'a> {
    #[serde(rename = "ruleId")]
    rule_id: &'a str,
    level: &'static str,
    message: SarifText<'a>,
    /// Omitted entirely for location-less findings — SARIF allows results
    /// without locations, and an empty array carries no information.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    locations: Vec<SarifLocation<'a>>,
}

#[derive(Serialize)]
struct SarifLocation<'a> {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation<'a>,
}

#[derive(Serialize)]
struct SarifPhysicalLocation<'a> {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation<'a>,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation<'a> {
    uri: &'a str,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
    #[serde(rename = "startColumn")]
    start_column: usize,
}

/// SARIF reporting level for a caracal impact.
fn sarif_level(impact: Impact) -> &'static str {
    match impact {
        Impact::High => "error",
        Impact::Medium => "warning",
        Impact::Low | Impact::Informational => "note",
    }
}

/// Render the findings as a SARIF 2.1.0 document. `detectors` is the set of
/// detectors that ran: each becomes a `rules[]` entry of the tool driver
/// (whether or not it produced findings), so consumers can tell "clean" from
/// "not checked".
pub fn render_sarif(results: &[Result], detectors: &[Box<dyn Detector>]) -> String {
    let rules = detectors
        .iter()
        .map(|d| SarifRule {
            id: d.name(),
            short_description: SarifText {
                text: d.description(),
            },
            default_configuration: SarifConfiguration {
                level: sarif_level(d.impact()),
            },
        })
        .collect();

    let sarif_results = results
        .iter()
        .map(|r| SarifResult {
            rule_id: &r.name,
            level: sarif_level(r.impact),
            message: SarifText { text: &r.message },
            locations: r
                .locations
                .iter()
                .map(|location| SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: &location.file,
                        },
                        region: SarifRegion {
                            start_line: location.line,
                            start_column: location.col,
                        },
                    },
                })
                .collect(),
        })
        .collect();

    let sarif = Sarif {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "caracal",
                    information_uri: "https://github.com/crytic/caracal",
                    version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            results: sarif_results,
        }],
    };
    serde_json::to_string_pretty(&sarif).expect("sarif serializes infallibly")
}

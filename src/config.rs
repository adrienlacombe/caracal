//! Project configuration file (`caracal.toml`) for `caracal detect`.
//!
//! Discovery: an explicit `--config <path>` wins; otherwise caracal looks for
//! `caracal.toml` in the analyzed target's directory (the target itself when
//! it is a directory, its parent when it is a file), then in the current
//! working directory. No ancestor walking. Every key is optional; per-setting
//! precedence is CLI flag > config file > built-in default (the CLI merge
//! lives in `src/cli/commands/detect/mod.rs`).
//!
//! Unknown keys are a hard error (`deny_unknown_fields`) so a typo like
//! `detectros` fails the run instead of being silently ignored.

use crate::detectors::detector::Impact;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// File name looked up during discovery.
pub const CONFIG_FILE_NAME: &str = "caracal.toml";

/// `--fail-on` threshold as spelled in the config file.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    High,
    Medium,
    Low,
    Informational,
}

impl From<FailOn> for Impact {
    fn from(level: FailOn) -> Self {
        match level {
            FailOn::High => Impact::High,
            FailOn::Medium => Impact::Medium,
            FailOn::Low => Impact::Low,
            FailOn::Informational => Impact::Informational,
        }
    }
}

/// `--format` as spelled in the config file.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Text,
    Json,
    Sarif,
}

/// The parsed `caracal.toml`. All keys optional; `None` means "not set, fall
/// through to the CLI default".
#[derive(Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Mirrors `--safe-external-calls`.
    pub safe_external_calls: Option<Vec<String>>,
    /// Mirrors `--detect` (run only these detectors). Mutually exclusive with
    /// `exclude_detectors`, like the CLI flags it mirrors.
    pub detectors: Option<Vec<String>>,
    /// Mirrors `--exclude`.
    pub exclude_detectors: Option<Vec<String>>,
    /// Mirrors `--fail-on`.
    pub fail_on: Option<FailOn>,
    /// Mirrors `--format`.
    pub format: Option<Format>,
    /// Mirrors `--baseline`. A relative path is resolved against the config
    /// file's directory at load time.
    pub baseline: Option<PathBuf>,
    /// Drop findings whose FIRST location's file path starts with any entry
    /// (literal prefix match on the `/`-separated target-relative path — end
    /// an entry with `/` to match a whole directory). Findings without a
    /// location are never path-filtered.
    pub exclude_paths: Option<Vec<String>>,
}

impl Config {
    /// Load and validate a config file. Errors carry the file path; a file
    /// that sets both `detectors` and `exclude_detectors` is rejected with
    /// the same mutual-exclusion rule the CLI enforces for
    /// `--detect`/`--exclude`.
    pub fn load(path: &Path) -> Result<Config> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {}", path.display()))?;
        let mut config = Self::parse(&content)
            .with_context(|| format!("invalid config file {}", path.display()))?;
        // Resolve the baseline path against the config file's directory, so
        // the config works whatever directory caracal is invoked from.
        if let Some(baseline) = &config.baseline {
            if baseline.is_relative() {
                if let Some(dir) = path.parent() {
                    config.baseline = Some(dir.join(baseline));
                }
            }
        }
        Ok(config)
    }

    /// Parse and validate config content (path-independent part of `load`).
    fn parse(content: &str) -> Result<Config> {
        let config: Config = toml::from_str(content)?;
        if config.detectors.is_some() && config.exclude_detectors.is_some() {
            bail!(
                "`detectors` and `exclude_detectors` are mutually exclusive — \
                 set at most one (same rule as the --detect/--exclude CLI flags)"
            );
        }
        Ok(config)
    }

    /// Discovery: `caracal.toml` next to the analyzed target, then in the
    /// current working directory. Returns the first existing file, if any.
    pub fn discover(target: &Path) -> Option<PathBuf> {
        let target_dir = if target.is_dir() {
            Some(target)
        } else {
            target.parent()
        };
        if let Some(dir) = target_dir {
            let candidate = dir.join(CONFIG_FILE_NAME);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        let cwd_candidate = PathBuf::from(CONFIG_FILE_NAME);
        if cwd_candidate.is_file() {
            return Some(cwd_candidate);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_keys() {
        let config = Config::parse(
            r#"
            safe_external_calls = ["::safe_foo"]
            detectors = ["reentrancy", "tx-origin"]
            fail_on = "high"
            format = "sarif"
            baseline = "ci/caracal-baseline.json"
            exclude_paths = ["tests/", "mocks/"]
            "#,
        )
        .unwrap();
        assert_eq!(
            config.safe_external_calls,
            Some(vec!["::safe_foo".to_string()])
        );
        assert_eq!(
            config.detectors,
            Some(vec!["reentrancy".to_string(), "tx-origin".to_string()])
        );
        assert_eq!(config.exclude_detectors, None);
        assert_eq!(config.fail_on, Some(FailOn::High));
        assert_eq!(config.format, Some(Format::Sarif));
        assert_eq!(
            config.baseline,
            Some(PathBuf::from("ci/caracal-baseline.json"))
        );
        assert_eq!(
            config.exclude_paths,
            Some(vec!["tests/".to_string(), "mocks/".to_string()])
        );
    }

    #[test]
    fn empty_config_is_all_none() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = Config::parse("detectros = [\"reentrancy\"]").unwrap_err();
        assert!(
            err.to_string().contains("detectros"),
            "error should name the unknown key: {err}"
        );
    }

    #[test]
    fn rejects_both_detector_lists() {
        let err = Config::parse(
            r#"
            detectors = ["reentrancy"]
            exclude_detectors = ["tx-origin"]
            "#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_invalid_enum_values() {
        assert!(Config::parse("fail_on = \"critical\"").is_err());
        assert!(Config::parse("format = \"xml\"").is_err());
    }

    #[test]
    fn load_resolves_relative_baseline_against_config_dir() {
        let dir = std::env::temp_dir().join(format!("caracal-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(CONFIG_FILE_NAME);
        std::fs::write(&path, "baseline = \"base.json\"").unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.baseline, Some(dir.join("base.json")));
        std::fs::remove_dir_all(&dir).ok();
    }
}

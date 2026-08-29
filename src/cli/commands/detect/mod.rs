use super::Cmd;
use caracal::{
    baseline,
    config::Config,
    core::core_unit::{CoreOpts, CoreUnit},
    detectors::{detector::Impact, detector::Result, get_detectors},
    output::{render_json, render_sarif},
};
use clap::{Args, ValueEnum, ValueHint};
use std::io::Write;
use std::path::PathBuf;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

/// How the findings are written to stdout. Whatever the format, stdout
/// carries only the findings document: compilation progress and warnings go
/// to stderr.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Human-readable colored text (the default)
    Text,
    /// A JSON array of findings
    Json,
    /// A SARIF 2.1.0 document
    Sarif,
}

impl From<caracal::config::Format> for OutputFormat {
    fn from(format: caracal::config::Format) -> Self {
        match format {
            caracal::config::Format::Text => OutputFormat::Text,
            caracal::config::Format::Json => OutputFormat::Json,
            caracal::config::Format::Sarif => OutputFormat::Sarif,
        }
    }
}

/// Impact threshold for `--fail-on`, ordered most severe first.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum FailOnImpact {
    High,
    Medium,
    Low,
    Informational,
}

impl From<FailOnImpact> for Impact {
    fn from(level: FailOnImpact) -> Self {
        match level {
            FailOnImpact::High => Impact::High,
            FailOnImpact::Medium => Impact::Medium,
            FailOnImpact::Low => Impact::Low,
            FailOnImpact::Informational => Impact::Informational,
        }
    }
}

#[derive(Args, Debug)]
#[command(after_help = "Exit codes:
  0    analysis ran (no --fail-on, or no finding at or above the threshold)
  1    at least one finding has impact at or above the --fail-on threshold
  2    caracal failed to run (compilation error, invalid target, ...)

Configuration:
  Options can also be set in a caracal.toml next to the analyzed target or in
  the current working directory (--config <path> overrides discovery). CLI
  flags win over the config file, per setting; the detector selection flags
  (--detect / --exclude / --exclude-*) win as a group over the config's
  detectors/exclude_detectors keys.")]
pub struct DetectArgs {
    /// Target to analyze
    #[arg(value_hint = ValueHint::FilePath)]
    target: PathBuf,

    /// Path to a caracal.toml configuration file (overrides discovery of
    /// caracal.toml in the target directory / current working directory)
    #[arg(long, value_hint = ValueHint::FilePath)]
    config: Option<PathBuf>,

    /// Corelib path (e.g. mypath/corelib/src); overrides CORELIB_PATH and the corelib bundled into the binary
    #[arg(long)]
    corelib: Option<PathBuf>,

    /// Path to the contracts to compile when using a cairo project with multiple contracts
    #[arg(long, num_args(0..))]
    contract_path: Option<Vec<String>>,

    /// Functions name that are safe when called (e.g. they don't cause a reentrancy)
    #[arg(long, num_args(0..))]
    safe_external_calls: Option<Vec<String>>,

    /// Detectors to run
    #[arg(long, num_args(0..), conflicts_with_all(["exclude", "exclude_informational", "exclude_low", "exclude_medium", "exclude_high"]))]
    detect: Option<Vec<String>>,

    /// Detectors to exclude
    #[arg(long, num_args(0..))]
    exclude: Option<Vec<String>>,

    /// Exclude detectors with informational impact
    #[arg(long)]
    exclude_informational: bool,

    /// Exclude detectors with low impact
    #[arg(long)]
    exclude_low: bool,

    /// Exclude detectors with medium impact
    #[arg(long)]
    exclude_medium: bool,

    /// Exclude detectors with high impact
    #[arg(long)]
    exclude_high: bool,

    /// Output format for the findings on stdout [default: text]
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// Exit with code 1 if any finding has impact at or above this threshold
    /// (High > Medium > Low > Informational); without it the exit code is 0
    /// whatever is found
    #[arg(long, value_enum)]
    fail_on: Option<FailOnImpact>,

    /// Baseline file of accepted findings: fingerprints listed in it are
    /// suppressed from the output and from --fail-on counting
    #[arg(long, value_hint = ValueHint::FilePath)]
    baseline: Option<PathBuf>,

    /// Write the current findings' fingerprints to the baseline file
    /// (--baseline or the config's `baseline`, default caracal-baseline.json)
    /// instead of reporting them, and exit 0
    #[arg(long)]
    write_baseline: bool,
}

/// The settings that can come from both the CLI and `caracal.toml`, after
/// applying precedence: CLI flag > config file > default, per setting. The
/// detector selection flags are the one grouped exception, documented on
/// [`Effective::merge`].
struct Effective {
    safe_external_calls: Option<Vec<String>>,
    detect: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    format: OutputFormat,
    fail_on: Option<Impact>,
    baseline: Option<PathBuf>,
    exclude_paths: Vec<String>,
}

impl Effective {
    fn merge(args: &DetectArgs, config: Config) -> Effective {
        // Detector selection: --detect and --exclude are mutually exclusive
        // on the CLI (clap `conflicts_with_all`), and `detectors` /
        // `exclude_detectors` are mutually exclusive in the config file
        // (rejected in `Config::load`). Across the two sources the selection
        // flags win as a GROUP: if any CLI selection flag is given, both
        // config keys are ignored — otherwise a config `detectors` key would
        // conflict with a CLI `--exclude-low` and there would be no way to
        // override the config from the command line.
        let cli_selects_detectors = args.detect.is_some()
            || args.exclude.is_some()
            || args.exclude_informational
            || args.exclude_low
            || args.exclude_medium
            || args.exclude_high;
        let (detect, exclude) = if cli_selects_detectors {
            (args.detect.clone(), args.exclude.clone())
        } else {
            (config.detectors, config.exclude_detectors)
        };

        Effective {
            safe_external_calls: args
                .safe_external_calls
                .clone()
                .or(config.safe_external_calls),
            detect,
            exclude,
            format: args
                .format
                .or(config.format.map(OutputFormat::from))
                .unwrap_or(OutputFormat::Text),
            fail_on: args
                .fail_on
                .map(Impact::from)
                .or(config.fail_on.map(Impact::from)),
            baseline: args.baseline.clone().or(config.baseline),
            exclude_paths: config.exclude_paths.unwrap_or_default(),
        }
    }
}

impl DetectArgs {
    /// Load the effective config file: `--config` if given, otherwise
    /// discovery next to the target then in the current working directory,
    /// otherwise an empty config (so runs without a caracal.toml behave
    /// exactly as before the config file existed).
    fn load_config(&self) -> anyhow::Result<Config> {
        let path = match &self.config {
            Some(path) => Some(path.clone()),
            None => Config::discover(&self.target),
        };
        match path {
            Some(path) => {
                eprintln!("Using configuration from {}", path.display());
                Config::load(&path)
            }
            None => Ok(Config::default()),
        }
    }
}

impl Cmd for DetectArgs {
    fn run(&self) -> anyhow::Result<()> {
        let config = self.load_config()?;
        let effective = Effective::merge(self, config);

        let core = CoreUnit::new(CoreOpts {
            target: self.target.clone(),
            corelib: self.corelib.clone(),
            contract_path: self.contract_path.clone(),
            safe_external_calls: effective.safe_external_calls.clone(),
        })?;
        let mut detectors = get_detectors();

        if let Some(detectors_to_run) = &effective.detect {
            detectors.retain(|d| detectors_to_run.contains(&d.name().to_string()));
        } else {
            if let Some(detectors_to_exclude) = &effective.exclude {
                detectors.retain(|d| !detectors_to_exclude.contains(&d.name().to_string()));
            }

            if self.exclude_informational {
                detectors.retain(|d| d.impact() != Impact::Informational);
            }

            if self.exclude_low {
                detectors.retain(|d| d.impact() != Impact::Low);
            }

            if self.exclude_medium {
                detectors.retain(|d| d.impact() != Impact::Medium);
            }

            if self.exclude_high {
                detectors.retain(|d| d.impact() != Impact::High);
            }
        }

        let mut results = detectors
            .iter()
            .flat_map(|d| d.run(&core))
            .collect::<Vec<Result>>();
        results.sort();

        // `exclude_paths` (config only): drop findings whose FIRST location's
        // file starts with any entry. Location-less findings are never
        // path-filtered. Applied before everything downstream — output,
        // --fail-on counting and baseline writing all see the filtered set.
        if !effective.exclude_paths.is_empty() {
            results.retain(|r| match r.locations.first() {
                Some(location) => !effective
                    .exclude_paths
                    .iter()
                    .any(|prefix| location.file.starts_with(prefix.as_str())),
                None => true,
            });
        }

        if self.write_baseline {
            let path = effective
                .baseline
                .unwrap_or_else(|| PathBuf::from(baseline::DEFAULT_BASELINE_FILE));
            let written = baseline::write(&path, &results)?;
            eprintln!(
                "Wrote {} finding fingerprint(s) for {} finding(s) to {}",
                written,
                results.len(),
                path.display()
            );
            return Ok(());
        }

        if let Some(path) = &effective.baseline {
            if path.is_file() {
                let known = baseline::load(path)?;
                let before = results.len();
                results.retain(|r| !known.contains(&baseline::fingerprint(r)));
                eprintln!(
                    "{} pre-existing findings suppressed by baseline",
                    before - results.len()
                );
            } else {
                eprintln!(
                    "Baseline file {} not found; no findings suppressed",
                    path.display()
                );
            }
        }

        match effective.format {
            OutputFormat::Text => print_text(&results)?,
            OutputFormat::Json => print_document(&render_json(&results))?,
            OutputFormat::Sarif => print_document(&render_sarif(&results, &detectors))?,
        }

        if let Some(threshold) = effective.fail_on {
            // `Impact`'s derived `Ord` follows declaration order, High first,
            // so "at least as severe as the threshold" is `<=`.
            if results.iter().any(|r| r.impact <= threshold) {
                std::process::exit(1);
            }
        }

        Ok(())
    }
}

/// Write a machine-readable document to stdout, flushed before any
/// `--fail-on` exit can bypass buffered-writer destructors.
fn print_document(document: &str) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{}", document)?;
    stdout.flush()?;
    Ok(())
}

/// The default human-readable output: one colored block per finding.
fn print_text(results: &[Result]) -> anyhow::Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    for r in results.iter() {
        match r.impact {
            Impact::High => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_intense(true))?;
                writeln!(&mut stdout, "{}", r)?;
            }
            Impact::Medium => {
                stdout.set_color(
                    ColorSpec::new()
                        .set_fg(Some(Color::Yellow))
                        .set_intense(true),
                )?;
                writeln!(&mut stdout, "{}", r)?;
            }
            Impact::Low => {
                stdout.set_color(
                    ColorSpec::new()
                        .set_fg(Some(Color::Green))
                        .set_intense(true),
                )?;
                writeln!(&mut stdout, "{}", r)?;
            }
            Impact::Informational => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)).set_intense(true))?;
                writeln!(&mut stdout, "{}", r)?;
            }
        }
    }

    stdout.reset()?;
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use caracal::config::{FailOn, Format};

    /// A `caracal detect <target>` with no other flags.
    fn bare_args() -> DetectArgs {
        DetectArgs {
            target: PathBuf::from("contract.cairo"),
            config: None,
            corelib: None,
            contract_path: None,
            safe_external_calls: None,
            detect: None,
            exclude: None,
            exclude_informational: false,
            exclude_low: false,
            exclude_medium: false,
            exclude_high: false,
            format: None,
            fail_on: None,
            baseline: None,
            write_baseline: false,
        }
    }

    #[test]
    fn defaults_without_config_or_flags() {
        let effective = Effective::merge(&bare_args(), Config::default());
        assert_eq!(effective.safe_external_calls, None);
        assert_eq!(effective.detect, None);
        assert_eq!(effective.exclude, None);
        assert_eq!(effective.format, OutputFormat::Text);
        assert_eq!(effective.fail_on, None);
        assert_eq!(effective.baseline, None);
        assert!(effective.exclude_paths.is_empty());
    }

    #[test]
    fn config_fills_unset_settings() {
        let config = Config {
            safe_external_calls: Some(vec!["::safe_foo".to_string()]),
            detectors: Some(vec!["reentrancy".to_string()]),
            fail_on: Some(FailOn::Medium),
            format: Some(Format::Sarif),
            baseline: Some(PathBuf::from("base.json")),
            exclude_paths: Some(vec!["tests/".to_string()]),
            ..Config::default()
        };
        let effective = Effective::merge(&bare_args(), config);
        assert_eq!(
            effective.safe_external_calls,
            Some(vec!["::safe_foo".to_string()])
        );
        assert_eq!(effective.detect, Some(vec!["reentrancy".to_string()]));
        assert_eq!(effective.format, OutputFormat::Sarif);
        assert_eq!(effective.fail_on, Some(Impact::Medium));
        assert_eq!(effective.baseline, Some(PathBuf::from("base.json")));
        assert_eq!(effective.exclude_paths, vec!["tests/".to_string()]);
    }

    #[test]
    fn cli_flags_win_over_config() {
        let mut args = bare_args();
        args.safe_external_calls = Some(vec!["::cli_safe".to_string()]);
        args.format = Some(OutputFormat::Json);
        args.fail_on = Some(FailOnImpact::High);
        args.baseline = Some(PathBuf::from("cli.json"));
        let config = Config {
            safe_external_calls: Some(vec!["::config_safe".to_string()]),
            fail_on: Some(FailOn::Low),
            format: Some(Format::Sarif),
            baseline: Some(PathBuf::from("config.json")),
            ..Config::default()
        };
        let effective = Effective::merge(&args, config);
        assert_eq!(
            effective.safe_external_calls,
            Some(vec!["::cli_safe".to_string()])
        );
        assert_eq!(effective.format, OutputFormat::Json);
        assert_eq!(effective.fail_on, Some(Impact::High));
        assert_eq!(effective.baseline, Some(PathBuf::from("cli.json")));
    }

    #[test]
    fn cli_detect_overrides_config_lists_as_a_group() {
        let mut args = bare_args();
        args.detect = Some(vec!["tx-origin".to_string()]);
        let config = Config {
            exclude_detectors: Some(vec!["tx-origin".to_string()]),
            ..Config::default()
        };
        let effective = Effective::merge(&args, config);
        assert_eq!(effective.detect, Some(vec!["tx-origin".to_string()]));
        // The config's exclude list is ignored, not merged: it would
        // contradict the CLI's explicit selection.
        assert_eq!(effective.exclude, None);
    }

    #[test]
    fn cli_impact_excludes_override_config_lists_as_a_group() {
        let mut args = bare_args();
        args.exclude_low = true;
        let config = Config {
            detectors: Some(vec!["reentrancy".to_string()]),
            ..Config::default()
        };
        let effective = Effective::merge(&args, config);
        assert_eq!(effective.detect, None);
        assert_eq!(effective.exclude, None);
    }

    #[test]
    fn config_exclude_list_applies_without_cli_selection() {
        let config = Config {
            exclude_detectors: Some(vec!["dead-code".to_string()]),
            ..Config::default()
        };
        let effective = Effective::merge(&bare_args(), config);
        assert_eq!(effective.detect, None);
        assert_eq!(effective.exclude, Some(vec!["dead-code".to_string()]));
    }
}

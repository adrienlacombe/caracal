use super::Cmd;
use caracal::{
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
  2    caracal failed to run (compilation error, invalid target, ...)")]
pub struct DetectArgs {
    /// Target to analyze
    #[arg(value_hint = ValueHint::FilePath)]
    target: PathBuf,

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

    /// Output format for the findings on stdout
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Exit with code 1 if any finding has impact at or above this threshold
    /// (High > Medium > Low > Informational); without it the exit code is 0
    /// whatever is found
    #[arg(long, value_enum)]
    fail_on: Option<FailOnImpact>,
}

impl From<&DetectArgs> for CoreOpts {
    fn from(args: &DetectArgs) -> Self {
        CoreOpts {
            target: args.target.clone(),
            corelib: args.corelib.clone(),
            contract_path: args.contract_path.clone(),
            safe_external_calls: args.safe_external_calls.clone(),
        }
    }
}

impl Cmd for DetectArgs {
    fn run(&self) -> anyhow::Result<()> {
        let core = CoreUnit::new(self.into())?;
        let mut detectors = get_detectors();

        if let Some(detectors_to_run) = &self.detect {
            detectors.retain(|d| detectors_to_run.contains(&d.name().to_string()));
        } else {
            if let Some(detectors_to_exclude) = &self.exclude {
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

        match self.format {
            OutputFormat::Text => print_text(&results)?,
            OutputFormat::Json => print_document(&render_json(&results))?,
            OutputFormat::Sarif => print_document(&render_sarif(&results, &detectors))?,
        }

        if let Some(threshold) = self.fail_on {
            // `Impact`'s derived `Ord` follows declaration order, High first,
            // so "at least as severe as the threshold" is `<=`.
            if results.iter().any(|r| r.impact <= Impact::from(threshold)) {
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

use clap::Parser;

use crate::cli::commands::Cmd;

mod cli;

fn main() {
    let args = cli::CliArgs::parse();

    if let Err(e) = args.command.run() {
        // Same rendering as returning the error from main (message + cause
        // chain), but with a distinct exit code: 2 means caracal itself
        // failed, while `detect --fail-on` reserves 1 for findings.
        eprintln!("Error: {:?}", e);
        std::process::exit(2);
    }
}

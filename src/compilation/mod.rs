use anyhow::{anyhow, Result};
use std::fs;

use cairo_lang_sierra::program::Program;
use cairo_lang_starknet_classes::abi::Contract;

use crate::core::core_unit::CoreOpts;

mod cairo_project;
mod corelib;
mod scarb;
mod standard;
pub mod utils;

pub struct ProgramCompiled {
    pub sierra: Program,
    pub abi: Contract,
}

/// Printed when caracal falls back to a local `starknet-compile` binary
/// because no corelib could be resolved for the bundled compiler.
pub(crate) fn warn_local_compiler_fallback(local_version: &str, corelib_err: &anyhow::Error) {
    eprintln!(
        "WARNING: no corelib is available for the bundled compiler ({corelib_err});\n\
         WARNING: falling back to the local `starknet-compile` binary ({}).\n\
         WARNING: `starknet-compile` has no inlining-strategy flag, so the analyzed SIERRA\n\
         WARNING: is compiled with default (aggressive) inlining and analysis quality is\n\
         WARNING: degraded: inlining-sensitive detectors (unused-arguments, unused-return,\n\
         WARNING: the reentrancy family and other detectors matching named function calls)\n\
         WARNING: may miss findings. Pass --corelib path/to/corelib/src or set the\n\
         WARNING: CORELIB_PATH environment variable to use the bundled compiler instead\n\
         WARNING: (see the Status notes in the README).",
        local_version.trim()
    );
}

pub fn compile(opts: CoreOpts) -> Result<Vec<ProgramCompiled>> {
    if opts.target.is_dir() {
        if let Ok(entries) = fs::read_dir(opts.target.as_path()) {
            for entry in entries.flatten() {
                if entry.file_name() == "Scarb.toml" {
                    println!("Compiling with Scarb. Found Scarb.toml.");
                    return scarb::compile(opts);
                } else if entry.file_name() == "cairo_project.toml" {
                    println!("Compiling with Cairo. Found cairo_project.toml.");
                    return cairo_project::compile(opts);
                }
            }
        }
        Err(anyhow!("Compilation framework not found."))
    } else {
        standard::compile(opts)
    }
}

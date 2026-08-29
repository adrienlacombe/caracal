use crate::compilation::compile;
use crate::core::compilation_unit::CompilationUnit;
use anyhow::Result;
use cairo_lang_sierra::extensions::core::{CoreLibfunc, CoreType};
use cairo_lang_sierra::program_registry::ProgramRegistry;
use cairo_lang_starknet_classes::keccak::starknet_keccak;
use num_bigint::BigInt;
use rayon::prelude::*;
use std::path::PathBuf;

pub struct CoreOpts {
    pub target: PathBuf,
    pub corelib: Option<PathBuf>,
    pub contract_path: Option<Vec<String>>,
    pub safe_external_calls: Option<Vec<String>>,
}

pub struct CoreUnit {
    compilation_units: Vec<CompilationUnit>,
    safe_external_calls: Option<Vec<String>>,
    /// `starknet_keccak` of every entry in `safe_external_calls`. These match
    /// the selector constant used by `call_contract_syscall` /
    /// `library_call_syscall` on cairo >= 2.11, where the callee's textual
    /// name is no longer present in sierra.
    safe_external_selectors: Option<Vec<BigInt>>,
}

impl CoreUnit {
    pub fn new(opts: CoreOpts) -> Result<Self> {
        let safe_external_calls = opts.safe_external_calls.clone();
        // The entry typically arrives in the form `::safe_foo` (how users
        // spell it on the CLI); starknet_keccak wants the bare method name.
        let safe_external_selectors = safe_external_calls.as_ref().map(|names| {
            names
                .iter()
                .map(|n| {
                    let name = n.trim_start_matches("::");
                    BigInt::from(starknet_keccak(name.as_bytes()))
                })
                .collect()
        });
        let program_compiled = compile(opts)?;
        let compilation_units = program_compiled
            .par_iter()
            .map(|p| {
                let mut compilation_unit = CompilationUnit::new(
                    p.sierra.clone(),
                    p.abi.clone(),
                    ProgramRegistry::<CoreType, CoreLibfunc>::new(&p.sierra).unwrap(),
                    p.source_map.clone(),
                );
                compilation_unit.analyze();
                compilation_unit
            })
            .collect();
        Ok(CoreUnit {
            compilation_units,
            safe_external_calls,
            safe_external_selectors,
        })
    }

    pub fn get_safe_external_selectors(&self) -> &Option<Vec<BigInt>> {
        &self.safe_external_selectors
    }

    pub fn get_compilation_units(&self) -> &Vec<CompilationUnit> {
        &self.compilation_units
    }

    pub fn get_safe_external_calls(&self) -> &Option<Vec<String>> {
        &self.safe_external_calls
    }
}

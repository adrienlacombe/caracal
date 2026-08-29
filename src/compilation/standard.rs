use anyhow::{anyhow, bail, Result};
use std::path::PathBuf;
use std::process;

use cairo_lang_compiler::db::RootDatabase;
use cairo_lang_compiler::diagnostics::DiagnosticsReporter;
use cairo_lang_compiler::project::setup_project;
use cairo_lang_compiler::CompilerConfig;
use cairo_lang_filesystem::db::init_dev_corelib;
use cairo_lang_filesystem::ids::CrateInput;
use cairo_lang_lowering::optimizations::config::Optimizations;
use cairo_lang_lowering::utils::InliningStrategy;
use cairo_lang_starknet::compile::compile_prepared_db;
use cairo_lang_starknet::contract::find_contracts;
use cairo_lang_starknet::starknet_plugin_suite;
use cairo_lang_starknet_classes::compiler_version::current_compiler_version_id;
use cairo_lang_starknet_classes::contract_class::ContractClass;

use super::ProgramCompiled;
use crate::core::core_unit::CoreOpts;
use crate::core::source_map::{SourceBase, SourceMap};

pub fn compile(opts: CoreOpts) -> Result<Vec<ProgramCompiled>> {
    // The bundled in-process compiler (which avoids function inlining, giving
    // the best detector results) is used whenever a corelib can be resolved:
    // --corelib, CORELIB_PATH, or the corelib vendored into this binary. A
    // local `starknet-compile` binary is only a last-resort fallback because
    // it compiles with default aggressive inlining, degrading analysis.
    match super::corelib::resolve(opts.corelib.as_ref()) {
        Ok(corelib) => bundled_compiler(opts, corelib),
        Err(corelib_err) => local_compiler_fallback(opts, corelib_err),
    }
}

fn local_compiler_fallback(
    opts: CoreOpts,
    corelib_err: anyhow::Error,
) -> Result<Vec<ProgramCompiled>> {
    let output = process::Command::new("starknet-compile")
        .arg("--version")
        .output();

    let version = match output {
        Ok(result) if result.status.success() => String::from_utf8(result.stdout)?,
        _ => bail!(
            "Unable to compile: no corelib is available for the bundled compiler \
             ({corelib_err}) and no local `starknet-compile` binary was found on PATH. \
             Pass --corelib path/to/corelib/src or set the CORELIB_PATH environment \
             variable (a matching corelib ships in the caracal repository under \
             corelib/), or install a Cairo toolchain providing starknet-compile."
        ),
    };

    super::warn_local_compiler_fallback(&version, &corelib_err);

    // We have to check the version because if it's >= 2.1.0 the compiler needs --single-file flag
    let version: Vec<&str> = version
        .split_whitespace()
        .nth(1)
        .unwrap()
        .split('.')
        .collect();
    let single_file_flag = version[0] >= "2" && version[1] >= "1";
    local_compiler(opts, single_file_flag)
}

fn bundled_compiler(opts: CoreOpts, corelib: PathBuf) -> Result<Vec<ProgramCompiled>> {
    // Progress goes to stderr: stdout is reserved for analysis output
    // (machine-readable when `--format json|sarif`).
    eprintln!(
        "Compiling with the bundled compiler {} (corelib: {})",
        current_compiler_version_id(),
        corelib.display()
    );

    let mut db = RootDatabase::builder()
        .with_default_plugin_suite(starknet_plugin_suite())
        // Since cairo 2.6 the default strategy inlines user functions into the
        // compiler-generated `__wrapper__*` entrypoints, which erases the named
        // FunctionCall statements many detectors rely on. Avoid inlining (only
        // `#[inline(always)]` is still honored) so the analyzed SIERRA keeps
        // user functions as separate, named functions.
        .with_optimizations(Optimizations::enabled_with_default_movable_functions(
            InliningStrategy::Avoid,
        ))
        .build()?;
    init_dev_corelib(&mut db, corelib);

    let main_crate_inputs = setup_project(&mut db, &opts.target)?;
    let main_crate_ids = CrateInput::into_crate_ids(&db, main_crate_inputs.clone());

    let compiler_config = CompilerConfig {
        replace_ids: true,
        // Don't fail compilation on cairo deprecation warnings emitted by the
        // fixture contracts, and only report diagnostics originating in the
        // user's main crates (not the corelib/starknet dispatcher plugins).
        diagnostics_reporter: DiagnosticsReporter::stderr()
            .allow_warnings()
            .with_crates(&main_crate_inputs),
        // Annotate the contract class with sierra statement → Cairo source
        // mappings (and per-function declaration sites) so findings can point
        // at file:line in the analyzed source.
        add_statements_code_locations: true,
        add_functions_debug_info: true,
        ..Default::default()
    };

    let contracts = find_contracts(&db, &main_crate_ids);
    if contracts.is_empty() {
        bail!("Contract not found.");
    }

    let mut contracts_arg = vec![];
    contracts.iter().for_each(|c| contracts_arg.push(c));

    let contract_classes = match compile_prepared_db(&db, &contracts_arg, compiler_config) {
        Ok(c) => c,
        Err(e) => bail!("Error when compiling contracts: {e:?}"),
    };

    let mut programs_compiled: Vec<ProgramCompiled> = vec![];

    // Source locations in findings are reported relative to the directory the
    // analyzed file lives in; locations outside it (corelib) are dropped.
    let source_bases: Vec<SourceBase> = opts
        .target
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .map(|root| {
            vec![SourceBase {
                root,
                prefix: String::new(),
            }]
        })
        .unwrap_or_default();

    for contract_class in contract_classes {
        let debug_info = contract_class
            .sierra_program_debug_info
            .as_ref()
            .expect("replace_ids was set");
        let source_map =
            (!source_bases.is_empty()).then(|| SourceMap::new(debug_info, &source_bases));
        // `true` populates the program's ids with the debug names carried in
        // `sierra_program_debug_info` (checked present above).
        let program = contract_class.extract_sierra_program(true).unwrap().program;

        programs_compiled.push(ProgramCompiled {
            sierra: program,
            abi: contract_class.abi.unwrap(),
            source_map,
        });
    }

    Ok(programs_compiled)
}

// NOTE: the `starknet-compile` binary does not expose an inlining-strategy
// flag, so this path compiles with the compiler's default (aggressive)
// inlining and detectors relying on named user functions may miss findings.
// It is only reached as a last-resort fallback when no corelib resolves
// (see `compile` above), and a degraded-analysis warning has been printed.
fn local_compiler(opts: CoreOpts, single_file_flag: bool) -> Result<Vec<ProgramCompiled>> {
    let output = if single_file_flag {
        process::Command::new("starknet-compile")
            .arg("--single-file")
            .arg(opts.target)
            .arg("--replace-ids")
            .output()?
    } else {
        process::Command::new("starknet-compile")
            .arg(opts.target)
            .arg("--replace-ids")
            .output()?
    };

    if !output.status.success() {
        bail!(anyhow!(
            "starknet-compile failed to compile.\n Status {}\n {}",
            output.status,
            String::from_utf8(output.stderr)?
        ));
    }

    let contract_class: ContractClass =
        serde_json::from_str(&String::from_utf8(output.stdout)?).unwrap();

    // Debug info must exist because we ran the compiler with --replace-ids;
    // `extract_sierra_program(true)` would silently skip name population
    // without it, so keep the explicit check.
    assert!(
        contract_class.sierra_program_debug_info.is_some(),
        "starknet-compile --replace-ids produced no debug info"
    );
    let sierra = contract_class.extract_sierra_program(true).unwrap().program;

    Ok(vec![ProgramCompiled {
        sierra,
        abi: contract_class.abi.unwrap(),
        // Pre-built by an external compiler: no source mapping available.
        source_map: None,
    }])
}

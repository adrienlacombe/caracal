//! Scarb project compilation.
//!
//! Preferred path: compile the project's SOURCES in-process with the bundled
//! compiler, configured from `scarb metadata` (crate roots, editions, cfg,
//! experimental features per compilation unit). This gives the same analysis
//! quality as the standalone/cairo-project flows: function inlining avoided
//! and Cairo source locations in findings.
//!
//! Fallback path: consume the pre-built sierra artifacts `scarb build`
//! produces (the historical behavior). Taken whenever in-process compilation
//! is not feasible; every trigger prints a note to stderr:
//!   - `scarb metadata` missing/failing or unparsable (scarb too old),
//!   - a compilation unit pulling in Cairo plugins the bundled compiler
//!     cannot expand (Rust procedural macros — scarb-only infrastructure —
//!     or builtin plugins caracal does not bundle),
//!   - `build-external-contracts` in a starknet-contract target (scarb-only
//!     contract selection semantics),
//!   - no corelib for the bundled compiler,
//!   - in-process compilation errors.
//!
//! On fallback the analyzed SIERRA keeps whatever inlining the artifact was
//! built with and findings carry no source locations.

use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use crate::compilation::ProgramCompiled;
use crate::core::core_unit::CoreOpts;
use crate::core::source_map::{SourceBase, SourceMap};
use cairo_lang_compiler::db::RootDatabase;
use cairo_lang_compiler::diagnostics::DiagnosticsReporter;
use cairo_lang_compiler::project::update_crate_roots_from_project_config;
use cairo_lang_compiler::CompilerConfig;
use cairo_lang_filesystem::cfg::{Cfg, CfgSet};
use cairo_lang_filesystem::db::{
    init_dev_corelib, CrateSettings, DependencySettings, Edition, ExperimentalFeaturesConfig,
};
use cairo_lang_filesystem::ids::{CrateLongId, SmolStrId};
use cairo_lang_lowering::optimizations::config::Optimizations;
use cairo_lang_lowering::utils::InliningStrategy;
use cairo_lang_project::{AllCratesConfig, ProjectConfig, ProjectConfigContent};
use cairo_lang_starknet::compile::compile_prepared_db;
use cairo_lang_starknet::contract::find_contracts;
use cairo_lang_starknet::starknet_plugin_suite;
use cairo_lang_starknet_classes::compiler_version::current_compiler_version_id;
use cairo_lang_starknet_classes::contract_class::ContractClass;
use cairo_lang_utils::ordered_hash_map::OrderedHashMap;
use cairo_lang_utils::Intern;

pub fn compile(opts: CoreOpts) -> Result<Vec<ProgramCompiled>> {
    match compile_in_process(&opts) {
        Ok(programs) => Ok(programs),
        Err(reason) => {
            // Diagnostics go to stderr: stdout is reserved for analysis
            // output (machine-readable when `--format json|sarif`).
            eprintln!(
                "NOTE: cannot compile this Scarb project in-process: {reason:#}\n\
                 NOTE: analyzing pre-built artifacts instead — source locations are unavailable\n\
                 NOTE: and analysis quality depends on how the artifacts were compiled: ensure\n\
                 NOTE: inlining-strategy = \"avoid\" and sierra-replace-ids = true under [cairo]\n\
                 NOTE: in Scarb.toml."
            );
            compile_from_artifacts(opts)
        }
    }
}

// ---------------------------------------------------------------------------
// In-process path: `scarb metadata` → RootDatabase → bundled compiler.
// ---------------------------------------------------------------------------

/// The `scarb metadata --format-version 1` fields caracal needs. Deliberately
/// hand-rolled serde structs instead of the scarb SDK: the schema is stable
/// and this avoids version-lockstep with scarb's crates.
#[derive(serde::Deserialize)]
struct Metadata {
    version: u64,
    packages: Vec<PackageMetadata>,
    compilation_units: Vec<CompilationUnitMetadata>,
}

#[derive(serde::Deserialize)]
struct PackageMetadata {
    id: String,
    name: String,
    version: String,
    edition: Option<String>,
    root: PathBuf,
    targets: Vec<TargetMetadata>,
    #[serde(default)]
    experimental_features: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct TargetMetadata {
    kind: String,
    name: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct CompilationUnitMetadata {
    package: String,
    target: TargetMetadata,
    /// Absent on scarb versions too old to report per-component data; the
    /// in-process path refuses to guess and falls back.
    components_data: Option<Vec<ComponentMetadata>>,
    #[serde(default)]
    cairo_plugins: Vec<PluginMetadata>,
    #[serde(default)]
    cfg: Vec<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct ComponentMetadata {
    /// Package id this component's sources come from.
    package: String,
    /// Crate name as referred to in Cairo code.
    name: String,
    /// The crate root file (`.../src/lib.cairo`).
    source_path: PathBuf,
    /// Component-level cfg override; `None` means the unit-level cfg applies.
    cfg: Option<Vec<serde_json::Value>>,
    /// Component id, referenced by `dependencies`. Falls back to `package`
    /// on scarb versions that don't emit it.
    id: Option<String>,
    dependencies: Option<Vec<ComponentDependency>>,
}

#[derive(serde::Deserialize)]
struct ComponentDependency {
    id: String,
}

#[derive(serde::Deserialize)]
struct PluginMetadata {
    package: String,
}

fn compile_in_process(opts: &CoreOpts) -> Result<Vec<ProgramCompiled>> {
    let metadata = scarb_metadata(opts.target.as_path())?;

    let contract_units: Vec<&CompilationUnitMetadata> = metadata
        .compilation_units
        .iter()
        .filter(|cu| cu.target.kind == "starknet-contract")
        .collect();
    if contract_units.is_empty() {
        bail!("the workspace has no starknet-contract compilation unit");
    }

    let packages: HashMap<&str, &PackageMetadata> = metadata
        .packages
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect();

    for cu in &contract_units {
        check_unit_feasible(cu, &packages)?;
    }

    let corelib = super::corelib::resolve(opts.corelib.as_ref())
        .context("no corelib is available for the bundled compiler")?;

    eprintln!(
        "Compiling Scarb project sources in-process with the bundled compiler {} (corelib: {})",
        current_compiler_version_id(),
        corelib.display()
    );

    let target_root = opts
        .target
        .canonicalize()
        .with_context(|| format!("cannot canonicalize {}", opts.target.display()))?;

    let mut programs_compiled: Vec<ProgramCompiled> = vec![];
    for cu in &contract_units {
        let unit_programs =
            compile_unit(cu, &packages, &corelib, &target_root).with_context(|| {
                format!(
                    "failed to compile the `{}` target in-process",
                    cu.target.name
                )
            })?;
        programs_compiled.extend(unit_programs);
    }

    if programs_compiled.is_empty() {
        bail!("no contract was found in any starknet-contract target");
    }

    // Parsed by scripts/corpus.sh to pin the analyzed-contract count on
    // in-process targets (the fallback path counts target/dev artifacts
    // instead); keep the format stable.
    eprintln!("Compiled {} contracts in-process", programs_compiled.len());

    Ok(programs_compiled)
}

/// Run `scarb metadata --format-version 1` in `target` and parse the JSON.
fn scarb_metadata(target: &Path) -> Result<Metadata> {
    let output = process::Command::new("scarb")
        .current_dir(target)
        .args(["metadata", "--format-version", "1"])
        .output()
        .context("failed to run `scarb metadata` (is scarb on PATH?)")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = if stderr.trim().is_empty() {
            stdout
        } else {
            stderr
        };
        bail!(
            "`scarb metadata` failed ({}): {}",
            output.status,
            summarize(&detail)
        );
    }

    // scarb prints `warn:` lines to stdout before the JSON document; skip to
    // the first line that starts the document.
    let json_start = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .map(|l| l.as_ptr() as usize - stdout.as_ptr() as usize)
        .ok_or_else(|| anyhow!("`scarb metadata` printed no JSON document"))?;
    let metadata: Metadata = serde_json::from_str(&stdout[json_start..])
        .context("cannot parse `scarb metadata` output (scarb version too old or too new?)")?;
    if metadata.version != 1 {
        bail!(
            "unsupported `scarb metadata` format version {}",
            metadata.version
        );
    }
    Ok(metadata)
}

/// Reject compilation units the bundled compiler cannot reproduce faithfully.
fn check_unit_feasible(
    cu: &CompilationUnitMetadata,
    packages: &HashMap<&str, &PackageMetadata>,
) -> Result<()> {
    // The only Cairo plugin the bundled compiler provides is the builtin
    // starknet plugin suite. Anything else — above all Rust procedural
    // macros, which need scarb's proc-macro infrastructure — cannot be
    // expanded in-process.
    let unsupported: Vec<&str> = cu
        .cairo_plugins
        .iter()
        .filter(|plugin| {
            let builtin_starknet = packages.get(plugin.package.as_str()).is_some_and(|p| {
                p.name == "starknet"
                    && p.targets.iter().any(|t| {
                        t.kind == "cairo-plugin"
                            && t.params.get("builtin").and_then(|b| b.as_bool()) == Some(true)
                    })
            });
            !builtin_starknet
        })
        .map(|plugin| {
            packages
                .get(plugin.package.as_str())
                .map(|p| p.name.as_str())
                .unwrap_or(plugin.package.as_str())
        })
        .collect();
    if !unsupported.is_empty() {
        bail!(
            "the `{}` target uses Cairo plugins/proc-macros the bundled compiler cannot expand: {}",
            cu.target.name,
            unsupported.join(", ")
        );
    }

    if cu.target.params.get("build-external-contracts").is_some() {
        bail!(
            "the `{}` target selects contracts with build-external-contracts, \
             which only scarb can reproduce",
            cu.target.name
        );
    }

    if cu.components_data.is_none() {
        bail!("`scarb metadata` reports no per-component data (scarb version too old)");
    }

    Ok(())
}

/// Compile one starknet-contract compilation unit in-process and return its
/// contracts, with source maps.
fn compile_unit(
    cu: &CompilationUnitMetadata,
    packages: &HashMap<&str, &PackageMetadata>,
    corelib: &Path,
    target_root: &Path,
) -> Result<Vec<ProgramCompiled>> {
    let components = cu
        .components_data
        .as_deref()
        .expect("checked by check_unit_feasible");

    // The crate identifier handed to the compiler is the crate NAME (so the
    // machine-specific package ids scarb uses as discriminators never leak
    // into diagnostics or output). That requires names to be unique within
    // the unit; scarb only violates that when two copies of one crate end up
    // in a single unit, which caracal does not model.
    let mut seen = HashSet::new();
    for component in components {
        if !seen.insert(component.name.as_str()) {
            bail!(
                "two crates named `{}` in one compilation unit",
                component.name
            );
        }
    }

    // Component id → (crate name, discriminator) for dependency wiring.
    // `update_crate_roots_from_project_config` derives each crate's
    // discriminator from its identifier (the name, except `core` which must
    // stay discriminator-less), so dependencies must reference exactly that.
    let by_id: HashMap<&str, &ComponentMetadata> = components
        .iter()
        .map(|c| (c.id.as_deref().unwrap_or(c.package.as_str()), c))
        .collect();

    let mut crate_roots = OrderedHashMap::default();
    let mut override_map = OrderedHashMap::default();
    for component in components {
        if component.name == "core" {
            // The corelib resolved by caracal's own chain is used instead
            // (init_dev_corelib below), keeping the corelib in lockstep with
            // the bundled compiler version.
            continue;
        }
        let root = component.source_path.parent().ok_or_else(|| {
            anyhow!(
                "crate root {} has no parent",
                component.source_path.display()
            )
        })?;
        if component.source_path.file_name().and_then(|f| f.to_str()) != Some("lib.cairo") {
            bail!(
                "crate `{}` has a non-standard root file {}",
                component.name,
                component.source_path.display()
            );
        }

        let package = packages.get(component.package.as_str());
        let edition = match package.and_then(|p| p.edition.as_deref()) {
            Some(edition) => serde_json::from_value(serde_json::Value::String(edition.into()))
                .with_context(|| {
                    format!(
                        "crate `{}` uses the unknown edition {edition}",
                        component.name
                    )
                })?,
            None => Edition::default(),
        };

        let mut dependencies = BTreeMap::new();
        for dep in component.dependencies.as_deref().unwrap_or_default() {
            let Some(dep_component) = by_id.get(dep.id.as_str()) else {
                // Typically the cairo-plugin pseudo-components (`starknet`),
                // which are not crates.
                continue;
            };
            let discriminator = (dep_component.name != "core").then(|| dep_component.name.clone());
            dependencies.insert(
                dep_component.name.clone(),
                DependencySettings { discriminator },
            );
        }

        let settings = CrateSettings {
            name: None,
            edition,
            version: package.and_then(|p| semver::Version::parse(&p.version).ok()),
            cfg_set: Some(parse_cfg(component.cfg.as_deref().unwrap_or(&cu.cfg))),
            dependencies,
            experimental_features: parse_experimental_features(
                package.and_then(|p| p.experimental_features.as_deref()),
            ),
        };

        crate_roots.insert(component.name.as_str().into(), root.to_path_buf());
        override_map.insert(component.name.as_str().into(), settings);
    }

    let main_component = components
        .iter()
        .find(|c| c.package == cu.package)
        .ok_or_else(|| anyhow!("compilation unit has no component for its own package"))?;

    let project_config = ProjectConfig {
        base_path: target_root.to_path_buf(),
        content: ProjectConfigContent {
            crate_roots,
            crates_config: AllCratesConfig {
                global: CrateSettings::default(),
                override_map,
            },
        },
    };

    let mut db = RootDatabase::builder()
        .with_default_plugin_suite(starknet_plugin_suite())
        // Same rationale as the standalone/cairo-project flows: avoid
        // inlining user functions so detectors keep seeing named calls.
        .with_optimizations(Optimizations::enabled_with_default_movable_functions(
            InliningStrategy::Avoid,
        ))
        .build()?;
    init_dev_corelib(&mut db, corelib.to_path_buf());
    update_crate_roots_from_project_config(&mut db, &project_config);

    let main_crate_id = CrateLongId::Real {
        name: SmolStrId::from(&db, main_component.name.as_str()),
        discriminator: Some(main_component.name.clone()),
    }
    .intern(&db);
    let main_crate_inputs = vec![main_crate_id.long(&db).clone().into_crate_input(&db)];

    let compiler_config = CompilerConfig {
        replace_ids: true,
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

    // Mirror scarb's default contract selection: the contracts declared in
    // the unit's own package (dependencies' contracts belong to their own
    // units; `build-external-contracts` was rejected above).
    let contracts = find_contracts(&db, &[main_crate_id]);
    if contracts.is_empty() {
        return Ok(vec![]);
    }
    let contracts_arg: Vec<_> = contracts.iter().collect();

    let contract_classes =
        compile_prepared_db(&db, &contracts_arg, compiler_config).map_err(|e| anyhow!("{e:#}"))?;

    let source_bases = source_bases(components, packages, target_root);

    let mut programs_compiled = vec![];
    for contract_class in contract_classes {
        let debug_info = contract_class
            .sierra_program_debug_info
            .as_ref()
            .expect("replace_ids was set");
        let source_map = SourceMap::new(debug_info, &source_bases);
        // `true` populates the program's ids with the debug names carried in
        // `sierra_program_debug_info` (checked present above).
        let program = contract_class.extract_sierra_program(true).unwrap().program;
        programs_compiled.push(ProgramCompiled {
            sierra: program,
            abi: contract_class.abi.unwrap(),
            source_map: Some(source_map),
        });
    }
    Ok(programs_compiled)
}

/// Where findings may point, and how to render each: the analyzed project
/// itself relative to its root (first, so workspace members win), then every
/// dependency living outside it (under Scarb's cache, at a machine-specific
/// absolute path) as `<dep-name>/<path within the dependency's package>`.
/// Corelib is deliberately not a base: its locations are dropped, like in
/// the standalone/cairo-project flows.
fn source_bases(
    components: &[ComponentMetadata],
    packages: &HashMap<&str, &PackageMetadata>,
    target_root: &Path,
) -> Vec<SourceBase> {
    let mut bases = vec![SourceBase {
        root: target_root.to_path_buf(),
        prefix: String::new(),
    }];
    for component in components {
        if component.name == "core" {
            continue;
        }
        let Some(package) = packages.get(component.package.as_str()) else {
            continue;
        };
        let Ok(root) = package.root.canonicalize() else {
            continue;
        };
        if root.starts_with(target_root) {
            continue;
        }
        bases.push(SourceBase {
            root,
            prefix: format!("{}/", component.name),
        });
    }
    bases
}

/// Parse a metadata cfg list — entries are either `"name"` or `[key, value]`.
fn parse_cfg(entries: &[serde_json::Value]) -> CfgSet {
    let mut cfg_set = CfgSet::new();
    for entry in entries {
        match entry {
            serde_json::Value::String(name) => cfg_set.insert(Cfg::name(name.clone())),
            serde_json::Value::Array(pair) => {
                if let [serde_json::Value::String(key), serde_json::Value::String(value)] =
                    pair.as_slice()
                {
                    cfg_set.insert(Cfg::kv(key.clone(), value.clone()));
                }
            }
            _ => {}
        }
    }
    cfg_set
}

fn parse_experimental_features(features: Option<&[String]>) -> ExperimentalFeaturesConfig {
    let features = features.unwrap_or_default();
    let enabled = |name: &str| features.iter().any(|f| f == name);
    ExperimentalFeaturesConfig {
        negative_impls: enabled("negative_impls"),
        associated_item_constraints: enabled("associated_item_constraints"),
        coupons: enabled("coupons"),
        user_defined_inline_macros: enabled("user_defined_inline_macros"),
        repr_ptrs: enabled("repr_ptrs"),
    }
}

/// First line of a (possibly multi-line) error blob, length-capped.
fn summarize(text: &str) -> String {
    let line = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let mut summary: String = line.chars().take(200).collect();
    if summary.len() < line.len() {
        summary.push('…');
    }
    summary
}

// ---------------------------------------------------------------------------
// Fallback path: pre-built sierra artifacts from `scarb build`.
// ---------------------------------------------------------------------------

// NOTE: this path consumes the sierra artifacts scarb produces, so caracal
// cannot control the inlining strategy here. Scarb users get the best
// analysis results by setting `inlining-strategy = "avoid"` in the `[cairo]`
// section of their profile (alongside `sierra-replace-ids = true`).
fn compile_from_artifacts(opts: CoreOpts) -> Result<Vec<ProgramCompiled>> {
    process::Command::new("scarb")
        .current_dir(opts.target.as_path())
        .arg("clean")
        .output()?;

    let output = process::Command::new("scarb")
        .current_dir(opts.target.as_path())
        .arg("build")
        .arg("--workspace")
        .output()?;

    if !output.status.success() {
        bail!(anyhow!(
            "Scarb failed to compile.\n Status {}\n {}",
            output.status,
            String::from_utf8(output.stdout)?
        ));
    }

    let mut sierra_files_path = vec![];

    if let Ok(entries) = fs::read_dir(opts.target.as_path().join(Path::new("target/dev"))) {
        let accepted_formats = [
            // For scarb <= 0.7.0
            ".sierra",
            ".contract_class",
        ];
        for entry in entries.flatten() {
            if accepted_formats.iter().any(|f| {
                entry
                    .path()
                    .file_stem()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .ends_with(*f)
            }) {
                sierra_files_path.push(entry.path());
            }
        }
    }

    if sierra_files_path.is_empty() {
        bail!(anyhow!("Compiled sierra files not found. Ensure in Scarb.toml you have\n[[target.starknet-contract]]\nsierra = true"));
    }

    let mut programs_compiled: Vec<ProgramCompiled> = vec![];

    for sierra_file in sierra_files_path {
        let contents =
            fs::read_to_string(sierra_file.as_path()).expect("Failed to read a sierra file");
        // In some cases a .sierra is made even for newer scarb version which does not have a contract class
        // and it is not needed for us so if we get an error we skip the file
        let contract_class: ContractClass = if let Ok(c) = serde_json::from_str(&contents) {
            c
        } else {
            continue;
        };
        // `extract_sierra_program(true)` silently skips name population when
        // debug info is absent — the skip-this-file semantics must stay here.
        let Some(debug_info) = contract_class.sierra_program_debug_info.as_ref() else {
            eprintln!("Skipping analysing file {}. Debug info not found. Ensure in Scarb.toml you have \n[cairo]\nsierra-replace-ids = true\n", sierra_file.to_str().unwrap());
            continue;
        };
        if debug_info.libfunc_names.is_empty()
            && debug_info.type_names.is_empty()
            && debug_info.user_func_names.is_empty()
        {
            eprintln!("Skipping analysing file {}. Debug info not found. If the file has code ensure in Scarb.toml you have \n[cairo]\nsierra-replace-ids = true\n", sierra_file.to_str().unwrap());
            continue;
        }

        let program = contract_class.extract_sierra_program(true).unwrap().program;
        programs_compiled.push(ProgramCompiled {
            sierra: program,
            abi: contract_class.abi.unwrap(),
            // Scarb artifacts don't carry the source-location annotations
            // caracal's bundled compiler emits: no source mapping available.
            source_map: None,
        });
    }

    Ok(programs_compiled)
}

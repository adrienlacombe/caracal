use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::analysis::taint::WrapperVariable;
use crate::core::compilation_unit::CompilationUnit;
use crate::core::core_unit::CoreUnit;
use crate::core::function::{Function, Type};
use crate::utils::{function_locations, function_summary, number_to_ordinal};
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::felt252::Felt252Concrete;
use cairo_lang_sierra::program::{GenStatement, Statement as SierraStatement};
use rustc_hash::FxHashSet;

/// A constructor that takes a `ContractAddress` (an owner, an admin, a
/// token, ...) and stores it without rejecting the zero address bricks the
/// contract when a deployment script passes an empty value: access control
/// gated on the stored address can never be satisfied (and, unlike EOA
/// chains, nobody can ever hold the zero address key). The check is cheap
/// and deploy-time-only, so its absence is worth flagging.
///
/// For each Constructor entrypoint the analysis runs on the user's
/// constructor body (with inlining avoided the `__wrapper__constructor`
/// deserializes calldata and calls it; on pre-inlined artifacts the body
/// often survives default inlining too, and a constructor fully inlined
/// into its wrapper has no typed parameters left and is skipped,
/// under-reporting). Each `ContractAddress` parameter is flagged when it
/// flows (taint) into the value of a storage write anywhere in the
/// constructor's call tree while no zero-check on it — a
/// `core::...PartialEq::{eq,ne}` / `::is_zero` / `::is_non_zero` call
/// (inlining avoided) or a raw `felt252_is_zero` (pre-inlined artifacts) —
/// happens anywhere in that tree. Parameters are mapped positionally into
/// callees, mirroring `unchecked_l1_handler_from`.
///
/// Confidence is Low: some contracts intentionally accept a zero address
/// (e.g. an optional module), and a check performed through a non-corelib
/// helper is missed.
#[derive(Default)]
pub struct UncheckedZeroOwner {}

impl Detector for UncheckedZeroOwner {
    fn name(&self) -> &str {
        "unchecked-zero-owner"
    }

    fn description(&self) -> &str {
        "Detect constructors storing a ContractAddress parameter without a zero-address check"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn impact(&self) -> Impact {
        Impact::Medium
    }

    fn run(&self, core: &CoreUnit) -> HashSet<Result> {
        let mut results: HashSet<Result> = HashSet::new();

        for compilation_unit in core.get_compilation_units() {
            for f in compilation_unit
                .functions()
                .filter(|f| *f.ty() == Type::Constructor)
            {
                let Some(body) = constructor_body(compilation_unit, f) else {
                    continue;
                };

                // Ordinal is counted over the user-visible parameters (the
                // builtins and the ContractState receiver excluded) so the
                // message matches the Cairo signature.
                let mut ordinal = 0u64;
                for param in body.params() {
                    let ty = param
                        .ty
                        .debug_name
                        .as_ref()
                        .map(|n| n.as_str())
                        .unwrap_or_default();
                    if ty.contains("ContractState") {
                        continue;
                    }
                    ordinal += 1;
                    if ty != "ContractAddress" {
                        continue;
                    }

                    let sources =
                        FxHashSet::from_iter([WrapperVariable::new(body.name(), param.id.id)]);

                    let mut visited = HashSet::new();
                    if !check_in_call_tree(
                        compilation_unit,
                        &sources,
                        body,
                        &mut visited,
                        is_written_to_storage,
                    ) {
                        continue;
                    }

                    let mut visited = HashSet::new();
                    if check_in_call_tree(
                        compilation_unit,
                        &sources,
                        body,
                        &mut visited,
                        is_zero_checked,
                    ) {
                        continue;
                    }

                    results.insert(Result {
                        name: self.name().to_string(),
                        impact: self.impact(),
                        confidence: self.confidence(),
                        message: format!(
                            "The {} parameter (a ContractAddress) is written to storage without a zero-address check in the constructor {}",
                            number_to_ordinal(ordinal),
                            function_summary(compilation_unit, &body.name())
                        ),
                        locations: function_locations(compilation_unit, &body.name()),
                    });
                }
            }
        }

        results
    }
}

/// The function holding the constructor's user-written body: the
/// `Contract::constructor` function the `Contract::__wrapper__constructor`
/// calls after deserializing the calldata (inlining avoided; the wrapper's
/// name is derived from the body's, so resolving by name skips the other
/// Private callees a wrapper can have — the `Serde::deserialize` impls of
/// custom parameter types live in the contract module too). A constructor
/// that is not a wrapper is its own body (pre-2.6 sierra, typed
/// parameters). `None` for a wrapper with everything inlined into it
/// (pre-built artifacts) — its only data parameter is the raw calldata
/// `Span`, so no `ContractAddress` parameter survives to check.
fn constructor_body<'a>(
    compilation_unit: &'a CompilationUnit,
    constructor: &'a Function,
) -> Option<&'a Function> {
    let name = constructor.name();
    if !name.contains("::__wrapper__") {
        return Some(constructor);
    }
    compilation_unit.function_by_name(&name.replacen("::__wrapper__", "::", 1))
}

/// True when a variable tainted by `sources` is the value of a storage write
/// in `function`. The written value is the last argument in every write
/// shape (the corelib accessor call, the pre-2.6 `InternalContractStateImpl
/// ::write`, and the raw `storage_write_syscall`), so keys of mapping writes
/// don't count — storing something *under* an address is not storing the
/// address.
fn is_written_to_storage(
    compilation_unit: &CompilationUnit,
    function: &Function,
    sources: &FxHashSet<WrapperVariable>,
) -> bool {
    let taint = compilation_unit.get_taint(&function.name()).unwrap();
    function.storage_vars_written().any(|stmt| {
        let GenStatement::Invocation(invoc) = stmt else {
            return false;
        };
        invoc.args.last().is_some_and(|value| {
            taint.taints_any_sources(sources, &WrapperVariable::new(function.name(), value.id))
        })
    })
}

/// True when a variable tainted by `sources` reaches a zero/equality check
/// in `function`.
fn is_zero_checked(
    compilation_unit: &CompilationUnit,
    function: &Function,
    sources: &FxHashSet<WrapperVariable>,
) -> bool {
    let taint = compilation_unit.get_taint(&function.name()).unwrap();
    function
        .get_statements()
        .iter()
        .filter_map(|stmt| match stmt {
            SierraStatement::Invocation(invoc) => Some(invoc),
            _ => None,
        })
        .any(|invoc| {
            let libfunc = compilation_unit
                .registry()
                .get_libfunc(&invoc.libfunc_id)
                .expect("Library function not found in the registry");

            match libfunc {
                // Pre-inlined artifacts: every comparison boils down to a
                // raw felt252_is_zero.
                CoreConcreteLibfunc::Felt252(Felt252Concrete::IsZero(_)) => taint
                    .taints_any_sources(
                        sources,
                        &WrapperVariable::new(function.name(), invoc.args[0].id),
                    ),
                // Inlining avoided: `== / !=` are corelib PartialEq impls,
                // `.is_zero()` / `.is_non_zero()` are corelib Zeroable/Zero
                // impls.
                CoreConcreteLibfunc::FunctionCall(f_called) => {
                    let callee = f_called
                        .function
                        .id
                        .debug_name
                        .as_ref()
                        .map(|n| n.as_str())
                        .unwrap_or_default();
                    let is_check = callee.starts_with("core::")
                        && (callee.ends_with("PartialEq::eq")
                            || callee.ends_with("PartialEq::ne")
                            || callee.ends_with("::is_zero")
                            || callee.ends_with("::is_non_zero"));
                    is_check
                        && invoc.args.iter().any(|arg| {
                            taint.taints_any_sources(
                                sources,
                                &WrapperVariable::new(function.name(), arg.id),
                            )
                        })
                }
                _ => false,
            }
        })
}

/// True when `local_check` holds for `function` (with `sources`) or, after
/// mapping the source variables positionally onto callee parameters, for any
/// function reachable through private/loop calls that the sources actually
/// flow into.
fn check_in_call_tree(
    compilation_unit: &CompilationUnit,
    sources: &FxHashSet<WrapperVariable>,
    function: &Function,
    visited: &mut HashSet<String>,
    local_check: fn(&CompilationUnit, &Function, &FxHashSet<WrapperVariable>) -> bool,
) -> bool {
    if local_check(compilation_unit, function, sources) {
        return true;
    }

    function
        .private_functions_calls()
        .chain(function.loop_functions_calls())
        .any(|s| {
            let GenStatement::Invocation(invoc) = s else {
                return false;
            };
            let libfunc = compilation_unit
                .registry()
                .get_libfunc(&invoc.libfunc_id)
                .expect("Library function not found in the registry");
            let CoreConcreteLibfunc::FunctionCall(f_called) = libfunc else {
                return false;
            };
            let Some(callee) = compilation_unit
                .function_by_name(f_called.function.id.debug_name.as_ref().unwrap())
            else {
                return false;
            };

            let taint = compilation_unit.get_taint(&function.name()).unwrap();
            let sinks: FxHashSet<WrapperVariable> = invoc
                .args
                .iter()
                .map(|v| WrapperVariable::new(function.name(), v.id))
                .collect();
            let callee_params: Vec<u64> = callee.params_all().map(|p| p.id.id).collect();

            let mapped_sources: FxHashSet<WrapperVariable> = sources
                .iter()
                .flat_map(|source| taint.taints_any_sinks_variable(source, &sinks))
                .filter_map(|sink| {
                    invoc
                        .args
                        .iter()
                        .position(|a| a.id == sink.variable())
                        .and_then(|pos| callee_params.get(pos))
                        .map(|param| WrapperVariable::new(callee.name(), *param))
                })
                .collect();

            if mapped_sources.is_empty() {
                return false;
            }
            if !visited.insert(callee.name()) {
                return false;
            }
            check_in_call_tree(
                compilation_unit,
                &mapped_sources,
                callee,
                visited,
                local_check,
            )
        })
}

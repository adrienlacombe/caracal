use super::detector::{Confidence, Detector, Impact, Result};
use crate::analysis::taint::WrapperVariable;
use crate::core::compilation_unit::CompilationUnit;
use crate::core::core_unit::CoreUnit;
use crate::core::function::{Function, Type};
use crate::utils::filter_builtins_from_returns;
use crate::utils::function_summary;
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::felt252::Felt252Concrete;
use cairo_lang_sierra::extensions::starknet::StarknetConcreteLibfunc;
use cairo_lang_sierra::program::{GenStatement, Statement as SierraStatement};
use fxhash::FxHashSet;
use std::collections::HashSet;

/// `replace_class_syscall` overwrites the contract's own class. If it is
/// reachable from an External entrypoint (directly or through private calls)
/// and no caller-address check happens anywhere in that call tree, anyone
/// can trigger the upgrade — even when the class hash itself is hardcoded or
/// operator-stored. This complements `controlled-replace-class` (tainted
/// hash): here the hash may be perfectly trusted and the problem is the
/// missing access control.
///
/// A "caller check" is a read of the caller address — a `FunctionCall` to
/// `core::starknet::info::get_caller_address` / `get_execution_info`
/// (inlining avoided) or a raw `get_execution_info*_syscall` libfunc
/// (pre-inlined artifacts) — whose result flows (taint) into an equality
/// check: a `core::...PartialEq::{eq,ne}` call (inlining avoided) or a raw
/// `felt252_is_zero` (pre-inlined artifacts). Constructors are not
/// entrypoints for this analysis.
///
/// Confidence is Low: access control implemented through components,
/// modifiers with unusual shapes, or a caller address returned from a callee
/// and compared in the parent frame may be missed, producing false
/// positives on protected upgrade paths.
#[derive(Default)]
pub struct UnprotectedReplaceClass {}

impl Detector for UnprotectedReplaceClass {
    fn name(&self) -> &str {
        "unprotected-replace-class"
    }

    fn description(&self) -> &str {
        "Detect replace_class_syscall reachable from an external function without a caller address check"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn impact(&self) -> Impact {
        Impact::High
    }

    fn run(&self, core: &CoreUnit) -> HashSet<Result> {
        let mut results: HashSet<Result> = HashSet::new();

        for compilation_unit in core.get_compilation_units() {
            for f in compilation_unit
                .functions()
                .filter(|f| *f.ty() == Type::External)
            {
                let mut visited = HashSet::new();
                if !Self::reaches_replace_class(compilation_unit, f, &mut visited) {
                    continue;
                }

                let mut checked_functions = HashSet::new();
                if self.is_caller_checked(
                    &FxHashSet::default(),
                    compilation_unit,
                    f,
                    &mut checked_functions,
                ) {
                    continue;
                }

                results.insert(Result {
                    name: self.name().to_string(),
                    impact: self.impact(),
                    confidence: self.confidence(),
                    message: format!(
                        "The external function {} can replace the contract class without a caller address check",
                        function_summary(compilation_unit, &f.name())
                    ),
                });
            }
        }

        results
    }
}

impl UnprotectedReplaceClass {
    /// True when the function contains a raw `replace_class_syscall` or one
    /// is reachable through its private/loop calls.
    fn reaches_replace_class(
        compilation_unit: &CompilationUnit,
        function: &Function,
        visited: &mut HashSet<String>,
    ) -> bool {
        if !visited.insert(function.name()) {
            return false;
        }

        for stmt in function.get_statements().iter() {
            let SierraStatement::Invocation(invoc) = stmt else {
                continue;
            };
            let libfunc = compilation_unit
                .registry()
                .get_libfunc(&invoc.libfunc_id)
                .expect("Library function not found in the registry");
            if matches!(
                libfunc,
                CoreConcreteLibfunc::Starknet(StarknetConcreteLibfunc::ReplaceClass(_))
            ) {
                return true;
            }
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
                compilation_unit
                    .function_by_name(f_called.function.id.debug_name.as_ref().unwrap())
                    .is_some_and(|callee| {
                        Self::reaches_replace_class(compilation_unit, callee, visited)
                    })
            })
    }

    /// True when a caller-address read in this function (or one flowing in
    /// from the caller's frame through `caller_sources`) reaches an equality
    /// check, here or in a callee. Mirrors the private-call recursion of
    /// `unchecked_l1_handler_from`, additionally collecting new sources in
    /// every visited function so modifier-style helpers (get the caller and
    /// compare it in the same private function) are recognized.
    fn is_caller_checked(
        &self,
        caller_sources: &FxHashSet<WrapperVariable>,
        compilation_unit: &CompilationUnit,
        function: &Function,
        checked_functions: &mut HashSet<String>,
    ) -> bool {
        let mut sources = caller_sources.clone();

        // Collect caller-address reads local to this function. Builtins are
        // filtered from the results so the GasBuiltin/System outputs don't
        // taint unrelated computations.
        for stmt in function.get_statements().iter() {
            let SierraStatement::Invocation(invoc) = stmt else {
                continue;
            };
            let libfunc = compilation_unit
                .registry()
                .get_libfunc(&invoc.libfunc_id)
                .expect("Library function not found in the registry");

            let output_infos = match libfunc {
                CoreConcreteLibfunc::FunctionCall(f_called) => {
                    let callee = f_called
                        .function
                        .id
                        .debug_name
                        .as_ref()
                        .map(|n| n.as_str())
                        .unwrap_or_default();
                    if callee == "core::starknet::info::get_caller_address"
                        || callee == "core::starknet::info::get_execution_info"
                    {
                        Some(&f_called.signature.branch_signatures[0].vars)
                    } else {
                        None
                    }
                }
                CoreConcreteLibfunc::Starknet(
                    StarknetConcreteLibfunc::GetExecutionInfo(g)
                    | StarknetConcreteLibfunc::GetExecutionInfoV2(g)
                    | StarknetConcreteLibfunc::GetExecutionInfoV3(g),
                ) => Some(&g.signature.branch_signatures[0].vars),
                _ => None,
            };

            if let (Some(output_infos), Some(branch)) = (output_infos, invoc.branches.first()) {
                for var in filter_builtins_from_returns(output_infos, branch.results.clone()) {
                    sources.insert(WrapperVariable::new(function.name(), var.id));
                }
            }
        }

        // Check whether any equality check in this function is tainted by a
        // caller-address read.
        let checked_locally = function
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
                    // Pre-inlined artifacts: comparisons boil down to a raw
                    // felt252_is_zero on the difference.
                    CoreConcreteLibfunc::Felt252(Felt252Concrete::IsZero(_)) => {
                        let taint = compilation_unit.get_taint(&function.name()).unwrap();
                        let sink = WrapperVariable::new(function.name(), invoc.args[0].id);
                        taint.taints_any_sources(&sources, &sink)
                    }
                    // With inlining avoided an equality check is a call into
                    // a corelib PartialEq impl.
                    CoreConcreteLibfunc::FunctionCall(f_called) => {
                        let callee = f_called
                            .function
                            .id
                            .debug_name
                            .as_ref()
                            .map(|n| n.as_str())
                            .unwrap_or_default();
                        if callee.starts_with("core::")
                            && (callee.ends_with("PartialEq::eq")
                                || callee.ends_with("PartialEq::ne"))
                        {
                            let taint = compilation_unit.get_taint(&function.name()).unwrap();
                            invoc.args.iter().any(|arg| {
                                taint.taints_any_sources(
                                    &sources,
                                    &WrapperVariable::new(function.name(), arg.id),
                                )
                            })
                        } else {
                            false
                        }
                    }
                    _ => false,
                }
            });

        if checked_locally {
            return true;
        }

        // Recurse into private/loop calls, mapping the caller-derived
        // variables used as call arguments to the callee's formal parameters
        // by position.
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
                if !checked_functions.insert(callee.name()) {
                    return false;
                }

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

                self.is_caller_checked(&mapped_sources, compilation_unit, callee, checked_functions)
            })
    }
}

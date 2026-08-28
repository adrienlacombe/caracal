use super::detector::{Confidence, Detector, Impact, Result};
use crate::analysis::taint::WrapperVariable;
use crate::core::compilation_unit::CompilationUnit;
use crate::core::core_unit::CoreUnit;
use crate::core::function::{Function, Type};
use crate::utils::{function_locations, function_summary};
use cairo_lang_sierra::extensions::{core::CoreConcreteLibfunc, felt252::Felt252Concrete};
use cairo_lang_sierra::ids::VarId;
use cairo_lang_sierra::program::{GenStatement, Statement as SierraStatement};
use fxhash::FxHashSet;
use std::collections::HashSet;

#[derive(Default)]
pub struct UncheckedL1HandlerFrom {}

impl Detector for UncheckedL1HandlerFrom {
    fn name(&self) -> &str {
        "unchecked-l1-handler-from"
    }

    fn description(&self) -> &str {
        "Detect L1 handlers without from address check"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn impact(&self) -> Impact {
        Impact::High
    }

    fn run(&self, core: &CoreUnit) -> HashSet<Result> {
        let mut results: HashSet<Result> = HashSet::new();
        let compilation_units = core.get_compilation_units();

        for compilation_unit in compilation_units {
            let l1_handler_funcs: Vec<_> = compilation_unit
                .functions()
                .filter(|f| *f.ty() == Type::L1Handler)
                .collect();

            for f in l1_handler_funcs {
                let mut sources = FxHashSet::default();
                if f.name().contains("::__wrapper__") {
                    // Since cairo 2.6 the handler entrypoint is a
                    // `__wrapper__*` whose only data parameter is the raw
                    // `Span<felt252>` calldata; `from_address` no longer
                    // exists as a parameter. The OS prepends it to the
                    // calldata, and deserialization runs before any user
                    // code, so the first deserialization of the wrapper pops
                    // exactly `from_address`. Two shapes exist:
                    // - inlining avoided (caracal's own compilation): a call
                    //   to `core::Felt252Serde::deserialize` whose 2nd result
                    //   is the deserialized `Option<felt252>` — seed with it
                    //   (the taint flows through the enum_match and into the
                    //   call to the user's handler function).
                    // - inlined sierra (e.g. scarb artifacts): a raw
                    //   `array_snapshot_pop_front<felt252>` — seed with the
                    //   popped box (the taint map flows it through `unbox`
                    //   and the stores on its own).
                    let from_var = f.get_statements().iter().find_map(|stmt| match stmt {
                        SierraStatement::Invocation(invoc)
                            if invoc.libfunc_id.debug_name.as_ref().is_some_and(|n| {
                                n.starts_with("array_snapshot_pop_front<felt252>")
                            }) =>
                        {
                            invoc
                                .branches
                                .first()
                                .and_then(|b| b.results.get(1))
                                .map(|v| v.id)
                        }
                        SierraStatement::Invocation(invoc)
                            if invoc.libfunc_id.debug_name.as_ref().is_some_and(|n| {
                                n == "function_call<user@core::Felt252Serde::deserialize>"
                            }) =>
                        {
                            invoc
                                .branches
                                .first()
                                .and_then(|b| b.results.get(1))
                                .map(|v| v.id)
                        }
                        _ => None,
                    });
                    let Some(from_var) = from_var else {
                        continue;
                    };
                    sources.insert(WrapperVariable::new(f.name(), from_var));
                } else {
                    // Pre-2.6 shape: the handler is its own function with the
                    // signature (self: @ContractState, from_address, ...) and
                    // `from_address` is the 2nd parameter.
                    let params_vec: Vec<VarId> = f.params().map(|p| p.id.clone()).collect();
                    if params_vec.len() < 2 {
                        continue;
                    }
                    sources.insert(WrapperVariable::new(f.name(), params_vec[1].id));
                }

                // Used to avoid infinite recursion in case of recursive private function calls
                let mut checked_private_functions = HashSet::new();

                // Check if any call to felt252_is_zero uses from_address argument
                let from_checked = self.is_from_checked_in_function(
                    &sources,
                    compilation_unit,
                    f,
                    &mut checked_private_functions,
                );

                if !from_checked {
                    let message = format!(
                        "The L1 handler function {} does not check the L1 from address",
                        function_summary(compilation_unit, &f.name())
                    );
                    results.insert(Result {
                        name: self.name().to_string(),
                        impact: self.impact(),
                        confidence: self.confidence(),
                        message,
                        locations: function_locations(compilation_unit, &f.name()),
                    });
                }
            }
        }

        results
    }
}

impl UncheckedL1HandlerFrom {
    fn is_from_checked_in_function(
        &self,
        from_tainted_args: &FxHashSet<WrapperVariable>,
        compilation_unit: &CompilationUnit,
        function: &Function,
        checked_private_functions: &mut HashSet<String>,
    ) -> bool {
        let from_checked = function
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
                    CoreConcreteLibfunc::Felt252(Felt252Concrete::IsZero(_)) => self
                        .is_felt252_is_zero_arg_tainted_by_from_address(
                            from_tainted_args,
                            invoc.args.clone(),
                            compilation_unit,
                            &function.name(),
                        ),
                    // With inlining avoided (cairo >= 2.6) an equality check
                    // is a call into a corelib PartialEq impl instead of the
                    // raw felt252_is_zero the impl performs internally.
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
                                    from_tainted_args,
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

        let from_checked_in_private_functions = from_checked
            || function.private_functions_calls().any(|s| {
                if let GenStatement::Invocation(invoc) = s {
                    let lib_func = compilation_unit
                        .registry()
                        .get_libfunc(&invoc.libfunc_id)
                        .expect("Library function not found in the registry");

                    if let CoreConcreteLibfunc::FunctionCall(f_called) = lib_func {
                        let private_function = compilation_unit
                            .function_by_name(f_called.function.id.debug_name.as_ref().unwrap())
                            .unwrap();
                        if checked_private_functions.contains(&private_function.name()) {
                            return false;
                        }

                        let taint = compilation_unit.get_taint(&function.name()).unwrap();

                        let sinks: FxHashSet<WrapperVariable> = invoc
                            .args
                            .iter()
                            .map(|v| WrapperVariable::new(function.name(), v.id))
                            .collect();

                        // The i-th call argument binds the callee's i-th
                        // parameter, so map tainted arguments to callee
                        // parameters by position. (The old id arithmetic
                        // `sink - args[0]` assumed consecutively numbered
                        // caller arguments, which post-2.6 codegen breaks.)
                        let callee_params: Vec<u64> =
                            private_function.params_all().map(|p| p.id.id).collect();

                        let from_tainted_args: FxHashSet<WrapperVariable> = from_tainted_args
                            .iter()
                            .flat_map(|source| taint.taints_any_sinks_variable(source, &sinks))
                            .filter_map(|sink| {
                                invoc
                                    .args
                                    .iter()
                                    .position(|a| a.id == sink.variable())
                                    .and_then(|pos| callee_params.get(pos))
                                    .map(|param| {
                                        WrapperVariable::new(private_function.name(), *param)
                                    })
                            })
                            .collect();

                        checked_private_functions.insert(private_function.name());
                        return self.is_from_checked_in_function(
                            &from_tainted_args,
                            compilation_unit,
                            private_function,
                            checked_private_functions,
                        );
                    }
                }
                false
            });

        from_checked_in_private_functions
    }

    fn is_felt252_is_zero_arg_tainted_by_from_address(
        &self,
        sources: &FxHashSet<WrapperVariable>,
        felt252_is_zero_args: Vec<VarId>,
        compilation_unit: &CompilationUnit,
        function_name: &str,
    ) -> bool {
        let sink = WrapperVariable::new(function_name.to_string(), felt252_is_zero_args[0].id);
        let taint = compilation_unit.get_taint(function_name).unwrap();
        // returns true If the felt252_is_zero arguments are tainted by the from_address
        taint.taints_any_sources(sources, &sink)
    }
}

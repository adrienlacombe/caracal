use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::analysis::taint::WrapperVariable;
use crate::core::compilation_unit::CompilationUnit;
use crate::core::core_unit::CoreUnit;
use crate::core::function::{Function, Type};
use crate::utils::{function_locations, function_summary};
use cairo_lang_sierra::extensions::array::ArrayConcreteLibfunc;
use cairo_lang_sierra::extensions::core::{CoreConcreteLibfunc, CoreTypeConcrete};
use cairo_lang_sierra::program::{GenStatement, Statement as SierraStatement};
use fxhash::FxHashSet;

#[derive(Default)]
pub struct UseAfterPopFront {}

enum CollectionType {
    Array,
    Span,
}

impl CollectionType {
    fn is_array(&self) -> bool {
        match self {
            CollectionType::Array => true,
            CollectionType::Span => false,
        }
    }
}

impl Detector for UseAfterPopFront {
    fn name(&self) -> &str {
        "use-after-pop-front"
    }

    fn description(&self) -> &str {
        "Detect use of an array or a span after removing element(s)"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn impact(&self) -> Impact {
        Impact::Low
    }

    fn run(&self, core: &CoreUnit) -> HashSet<Result> {
        let mut results: HashSet<Result> = HashSet::new();
        let compilation_units = core.get_compilation_units();

        for compilation_unit in compilation_units.iter() {
            for function in compilation_unit.functions_user_defined() {
                let pop_fronts: Vec<(usize, WrapperVariable, CollectionType)> = function
                    .get_statements()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, stmt)| match stmt {
                        SierraStatement::Invocation(invoc) => {
                            let libfunc = compilation_unit
                                .registry()
                                .get_libfunc(&invoc.libfunc_id)
                                .expect("Library function not found in the registry");

                            // Skip pops on the wrapper's calldata/serde buffer:
                            // since cairo 2.6 the compiler inlines
                            // `Serde::deserialize` — which pops felt252s — into
                            // every entrypoint wrapper. Those are compiler
                            // plumbing, not user intent.
                            let is_felt252_pop =
                                invoc.libfunc_id.debug_name.as_ref().is_some_and(|n| {
                                    n.ends_with("<felt252>") || n.contains("<core::felt252>")
                                });
                            if is_felt252_pop {
                                return None;
                            }

                            match libfunc {
                                CoreConcreteLibfunc::Array(ArrayConcreteLibfunc::PopFront(_)) => {
                                    Some((
                                        index,
                                        WrapperVariable::new(function.name(), invoc.args[0].id),
                                        CollectionType::Array,
                                    ))
                                }
                                CoreConcreteLibfunc::Array(
                                    ArrayConcreteLibfunc::SnapshotPopFront(_),
                                ) => Some((
                                    index,
                                    WrapperVariable::new(function.name(), invoc.args[0].id),
                                    CollectionType::Span,
                                )),
                                CoreConcreteLibfunc::Array(
                                    ArrayConcreteLibfunc::SnapshotPopBack(_),
                                ) => Some((
                                    index,
                                    WrapperVariable::new(function.name(), invoc.args[0].id),
                                    CollectionType::Span,
                                )),
                                // With inlining avoided (cairo >= 2.6) the pops
                                // are calls into the corelib array/span impls
                                // instead of raw array libfuncs. The collection
                                // is the only data argument (`ref self`).
                                CoreConcreteLibfunc::FunctionCall(f_called) => {
                                    let callee = f_called
                                        .function
                                        .id
                                        .debug_name
                                        .as_ref()
                                        .map(|n| n.as_str())
                                        .unwrap_or_default();
                                    if callee.starts_with("core::array::ArrayImpl::")
                                        && callee.ends_with("::pop_front")
                                    {
                                        Some((
                                            index,
                                            WrapperVariable::new(function.name(), invoc.args[0].id),
                                            CollectionType::Array,
                                        ))
                                    } else if callee.starts_with("core::array::SpanImpl::")
                                        && (callee.ends_with("::pop_front")
                                            || callee.ends_with("::pop_back"))
                                    {
                                        Some((
                                            index,
                                            WrapperVariable::new(function.name(), invoc.args[0].id),
                                            CollectionType::Span,
                                        ))
                                    } else {
                                        None
                                    }
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    })
                    .collect();

                // Required to silence clippy too-complex-type warning
                type BadCollectionType<'a> = Vec<(usize, &'a CollectionType)>;

                let (bad_array_used, bad_span_used): (BadCollectionType, BadCollectionType) =
                    pop_fronts
                        .iter()
                        .filter_map(|(index, bad_array, collection_type)| {
                            let is_used = self.is_used_after_pop_front(
                                compilation_unit,
                                function,
                                bad_array,
                                *index,
                            );
                            if is_used {
                                Some((*index, collection_type))
                            } else {
                                None
                            }
                        })
                        .partition(|(_, collection_type)| collection_type.is_array());

                // The popped collections have no names at the sierra level and
                // their VarIds are renumbered on every compiler bump, so refer
                // to them by their pop order within the function among pops of
                // the same kind (#1 = the first array/span popped).
                let pop_ordinal = |stmt_index: usize, is_array: bool| {
                    pop_fronts
                        .iter()
                        .filter(|(_, _, ct)| ct.is_array() == is_array)
                        .position(|(i, _, _)| *i == stmt_index)
                        .map(|p| p + 1)
                        .unwrap_or(0)
                };

                if !bad_array_used.is_empty() {
                    let array_ids = bad_array_used
                        .iter()
                        .map(|(i, _)| format!("#{}", pop_ordinal(*i, true)))
                        .collect::<Vec<String>>();
                    let message = match array_ids.len() {
                        1 => format!(
                            "The array {} is used after removing elements from it in the function {}",
                            array_ids[0],
                            function_summary(compilation_unit, &function.name())
                        ),
                        _ => format!(
                            "The arrays {} are used after removing elements from them in the function {}",
                            array_ids.join(", "),
                            function_summary(compilation_unit, &function.name())
                        )
                    };
                    results.insert(Result {
                        name: self.name().to_string(),
                        impact: self.impact(),
                        confidence: self.confidence(),
                        message,
                        locations: function_locations(compilation_unit, &function.name()),
                    });
                }

                if !bad_span_used.is_empty() {
                    let span_ids = bad_span_used
                        .iter()
                        .map(|(i, _)| format!("#{}", pop_ordinal(*i, false)))
                        .collect::<Vec<String>>();
                    let message = match span_ids.len() {
                        1 => format!(
                            "The span {} is used after removing elements from it in the function {}",
                            span_ids[0],
                            function_summary(compilation_unit, &function.name())
                        ),
                        _ => format!(
                            "The spans {} are used after removing elements from them in the function {}",
                            span_ids.join(", "),
                            function_summary(compilation_unit, &function.name())
                        )
                    };
                    results.insert(Result {
                        name: self.name().to_string(),
                        impact: self.impact(),
                        confidence: self.confidence(),
                        message,
                        locations: function_locations(compilation_unit, &function.name()),
                    });
                }
            }
        }

        results
    }
}

impl UseAfterPopFront {
    fn is_used_after_pop_front(
        &self,
        compilation_unit: &CompilationUnit,
        function: &Function,
        bad_array: &WrapperVariable,
        pop_stmt_index: usize,
    ) -> bool {
        // Check the remaining statements of the function. Start after the pop
        // statement itself: when the pop is a corelib FunctionCall it would
        // otherwise match the FunctionCall arm of `check_statements` and
        // count as its own "use".
        let bad_array_used_in_function =
            self.check_statements(compilation_unit, function, bad_array, pop_stmt_index + 1);

        // Check if the bad array is sent to any function being called from this function
        let bad_array_used_in_calls = bad_array_used_in_function
            || self.check_calls(
                compilation_unit,
                function,
                bad_array,
                &mut function
                    .private_functions_calls()
                    .chain(function.library_functions_calls())
                    .chain(function.external_functions_calls())
                    .chain(function.events_emitted()),
            );

        // Check the caller of the current function
        bad_array_used_in_calls || self.check_returns(compilation_unit, function, bad_array)
    }

    // Analyse the statements of the function after the pop_front statement
    // to see if the popped array is used again — either appended to, wrapped
    // into a Span for serde/emit, passed to a user function (e.g. the
    // compiler-generated serialize helper), or handed to a syscall.
    fn check_statements(
        &self,
        compilation_unit: &CompilationUnit,
        function: &Function,
        bad_array: &WrapperVariable,
        stmt_index: usize,
    ) -> bool {
        let taint = compilation_unit.get_taint(&function.name()).unwrap();

        function
            .get_statements_at(stmt_index)
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

                // Libfuncs that represent an actual "use" of the array. We
                // deliberately exclude plumbing like store_temp/branch_align/
                // redeposit_gas/drop and pure metadata reads like array_len.
                let is_use = match libfunc {
                    // Direct mutation.
                    CoreConcreteLibfunc::Array(ArrayConcreteLibfunc::Append(_)) => true,
                    // Forwarded to a user/core function (serialize_array_helper,
                    // dispatcher impls, etc.). A loop body passes the array to
                    // its own next iteration — that's not a leak, just the
                    // normal consume pattern.
                    CoreConcreteLibfunc::FunctionCall(call) => call
                        .function
                        .id
                        .debug_name
                        .as_ref()
                        .is_none_or(|n| *n != function.name()),
                    // Handed directly to a syscall (call_contract, library_call,
                    // emit_event, …).
                    CoreConcreteLibfunc::Starknet(_) => true,
                    // Wrapping the popped array into a Span (serde / event /
                    // external call path). The libfunc id encodes the struct
                    // generic, so match on its textual form. Inside a Loop
                    // function, this is just the inner body repackaging the
                    // remainder for the next iteration and is not a leak.
                    CoreConcreteLibfunc::Struct(_) => {
                        !matches!(function.ty(), Type::Loop)
                            && invoc.libfunc_id.debug_name.as_ref().is_some_and(|n| {
                                n.starts_with("struct_construct<core::array::Span::")
                            })
                    }
                    _ => false,
                };

                if !is_use {
                    return false;
                }

                let sinks: FxHashSet<WrapperVariable> = invoc
                    .args
                    .iter()
                    .map(|a| WrapperVariable::new(function.name(), a.id))
                    .collect();
                taint.taints_any_sinks(bad_array, &sinks)
            })
    }

    fn check_calls<'a>(
        &self,
        compilation_unit: &CompilationUnit,
        function: &Function,
        bad_array: &WrapperVariable,
        calls: &mut impl Iterator<Item = &'a SierraStatement>,
    ) -> bool {
        let taint = compilation_unit.get_taint(&function.name()).unwrap();

        calls.any(|s| {
            if let GenStatement::Invocation(invoc) = s {
                let lib_func = compilation_unit
                    .registry()
                    .get_libfunc(&invoc.libfunc_id)
                    .expect("Library function not found in the registry");

                if let CoreConcreteLibfunc::FunctionCall(_) = lib_func {
                    let sinks: FxHashSet<WrapperVariable> = invoc
                        .args
                        .iter()
                        .map(|v| WrapperVariable::new(function.name(), v.id))
                        .collect();

                    return taint.taints_any_sinks(bad_array, &sinks);
                }
            }
            false
        })
    }

    // check if the bad array is returned by the function
    // if yes then check if its a loop function
    // if yes then we need to check its caller to see if it uses the bad array
    // if not then its clear usage of a bad array
    fn check_returns(
        &self,
        compilation_unit: &CompilationUnit,
        function: &Function,
        bad_array: &WrapperVariable,
    ) -> bool {
        // No need to check remaining statements of the caller function
        // as returning a bad array is already a use of the bad array
        // if the current function is not a loop function
        match function.ty() {
            Type::Loop => self.check_loop_returns(compilation_unit, function, bad_array),
            _ => self.check_non_loop_returns(compilation_unit, function, bad_array),
        }
    }

    fn check_loop_returns(
        &self,
        compilation_unit: &CompilationUnit,
        function: &Function,
        bad_array: &WrapperVariable,
    ) -> bool {
        // We can not find the array from the return types of the function
        // We assume that the array is returned at the same index as it was taken on
        let return_array_indices: Vec<usize> = function
            .params_all()
            .enumerate()
            .filter_map(|(i, param)| {
                let param_type = compilation_unit
                    .registry()
                    .get_type(&param.ty)
                    .expect("Type not found in the registry");

                match param_type {
                    CoreTypeConcrete::Array(_) => Some(i),
                    span if self.is_core_type_concrete_span(compilation_unit, span) => Some(i),
                    _ => None,
                }
            })
            .collect();

        // In case the functon is a loop function, we need to check
        // the remaining statements of the caller function to see if they used the bad array
        compilation_unit
            .functions_user_defined()
            .any(|maybe_caller| {
                maybe_caller
                    .loop_functions_calls()
                    .flat_map(|f| {
                        if let GenStatement::Invocation(invoc) = f {
                            let lib_func = compilation_unit
                                .registry()
                                .get_libfunc(&invoc.libfunc_id)
                                .expect("Library function not found in the registry");

                            if let CoreConcreteLibfunc::FunctionCall(f_called) = lib_func {
                                if function.name().as_str()
                                    == f_called.function.id.debug_name.as_ref().unwrap()
                                {
                                    return return_array_indices
                                        .iter()
                                        .map(|i| {
                                            WrapperVariable::new(
                                                maybe_caller.name(),
                                                invoc.branches[0].results[*i].id,
                                            )
                                        })
                                        .collect();
                                }
                            }
                        }
                        Vec::new()
                    })
                    .any(|caller_bad_array| {
                        self.check_statements(compilation_unit, maybe_caller, &caller_bad_array, 0)
                            || self.check_calls(
                                compilation_unit,
                                function,
                                bad_array,
                                &mut maybe_caller
                                    .private_functions_calls()
                                    .chain(maybe_caller.library_functions_calls())
                                    .chain(maybe_caller.external_functions_calls())
                                    .chain(maybe_caller.events_emitted()),
                            )
                    })
            })
    }

    fn check_non_loop_returns(
        &self,
        compilation_unit: &CompilationUnit,
        function: &Function,
        bad_array: &WrapperVariable,
    ) -> bool {
        let taint = compilation_unit.get_taint(&function.name()).unwrap();

        // With inlining avoided the user function returns its value wrapped
        // in `PanicResult<(ContractState?, T)>`, so unwrap enums/structs when
        // looking for a returned array or span.
        let returns_array = function
            .returns_all()
            .any(|r| self.type_contains_array_or_span(compilation_unit, r, 0));

        // Not returning any array
        if !returns_array {
            return false;
        }

        // It is not required because taint analysis adds all the arugments as
        // tainters of the all the return values. Added it in case the taint
        // analysis is improved later on to be more granular.
        let returned_bad_arrays: Vec<WrapperVariable> = function
            .get_statements()
            .iter()
            .flat_map(|s| {
                if let GenStatement::Return(return_vars) = s {
                    let sinks: FxHashSet<WrapperVariable> = return_vars
                        .iter()
                        .map(|v| WrapperVariable::new(function.name(), v.id))
                        .collect();

                    return taint.taints_any_sinks_variable(bad_array, &sinks);
                }
                Vec::new()
            })
            .collect();

        !returned_bad_arrays.is_empty()
    }

    // Return true if the type is an array/span or (recursively) contains one,
    // unwrapping the PanicResult enum and tuple structs the compiler wraps
    // return values in when the function call is not inlined. Only the
    // success variant of PanicResult is considered — its error variant always
    // carries the `Array<felt252>` panic data and would match every function.
    fn type_contains_array_or_span(
        &self,
        compilation_unit: &CompilationUnit,
        ty_id: &cairo_lang_sierra::ids::ConcreteTypeId,
        depth: usize,
    ) -> bool {
        if depth > 4 {
            return false;
        }
        let ty = compilation_unit
            .registry()
            .get_type(ty_id)
            .expect("Type not found in the registry");
        match ty {
            CoreTypeConcrete::Array(_) => true,
            span if self.is_core_type_concrete_span(compilation_unit, span) => true,
            CoreTypeConcrete::Struct(struct_type) => struct_type
                .members
                .iter()
                .any(|m| self.type_contains_array_or_span(compilation_unit, m, depth + 1)),
            CoreTypeConcrete::Enum(enum_type) => {
                let is_panic_result = ty_id
                    .debug_name
                    .as_ref()
                    .is_some_and(|n| n.starts_with("core::panics::PanicResult"));
                if is_panic_result {
                    enum_type.variants.first().is_some_and(|v| {
                        self.type_contains_array_or_span(compilation_unit, v, depth + 1)
                    })
                } else {
                    enum_type
                        .variants
                        .iter()
                        .any(|v| self.type_contains_array_or_span(compilation_unit, v, depth + 1))
                }
            }
            _ => false,
        }
    }

    // The Span is not a Core Sierra type, it is defined in the corelib as a Struct
    // Therefore we can not match it against CoreTypeConcrete::Span directly
    fn is_core_type_concrete_span(
        &self,
        compilation_unit: &CompilationUnit,
        maybe_span: &CoreTypeConcrete,
    ) -> bool {
        match maybe_span {
            CoreTypeConcrete::Struct(struct_type) => match &struct_type.members[..] {
                [maybe_snapshot, ..] => {
                    let maybe_snapshot_type = compilation_unit
                        .registry()
                        .get_type(maybe_snapshot)
                        .expect("Type not found in the registry");

                    match maybe_snapshot_type {
                        CoreTypeConcrete::Snapshot(maybe_array) => {
                            let maybe_array_type = compilation_unit
                                .registry()
                                .get_type(&maybe_array.ty)
                                .expect("Type not found in the registry");

                            matches!(maybe_array_type, CoreTypeConcrete::Array(_))
                        }
                        _ => false,
                    }
                }
                _ => false,
            },
            _ => false,
        }
    }
}

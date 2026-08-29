use super::detector::{Confidence, Detector, Impact, Result};
use crate::core::compilation_unit::CompilationUnit;
use crate::core::core_unit::CoreUnit;
use crate::core::function::{Function, Type};
use crate::utils::{function_locations, function_summary, is_caller_checked};
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::starknet::StarknetConcreteLibfunc;
use cairo_lang_sierra::program::{GenStatement, Statement as SierraStatement};
use rustc_hash::FxHashSet;
use std::collections::HashSet;

/// `replace_class_syscall` overwrites the contract's own class. If it is
/// reachable from an External entrypoint (directly or through private calls)
/// and no caller-address check happens anywhere in that call tree, anyone
/// can trigger the upgrade — even when the class hash itself is hardcoded or
/// operator-stored. This complements `controlled-replace-class` (tainted
/// hash): here the hash may be perfectly trusted and the problem is the
/// missing access control.
///
/// The caller-check recognition is the shared `utils::is_caller_checked`
/// (see its docs for the recognized shapes). Constructors are not
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
                if is_caller_checked(
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
                    locations: function_locations(compilation_unit, &f.name()),
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
}

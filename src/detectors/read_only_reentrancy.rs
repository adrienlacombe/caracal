use super::detector::{Confidence, Detector, Impact, Result};
use crate::analysis::dataflow::AnalysisState;
use crate::analysis::reentrancy::ReentrancyDomain;
use crate::core::core_unit::CoreUnit;
use crate::core::function::Function;
use crate::core::function::Type;
use crate::utils::{
    is_safe_external_call, statement_summary_in_named_function, storage_identity_pretty,
    storage_statement_identity,
};
use std::collections::HashMap;
use std::collections::HashSet;

#[derive(Default)]
pub struct ReadOnlyReentrancy;

impl Detector for ReadOnlyReentrancy {
    fn name(&self) -> &str {
        "read-only-reentrancy"
    }

    fn description(&self) -> &str {
        "Detect when a view function read a storage variable written after an external call"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn impact(&self) -> Impact {
        Impact::Medium
    }

    fn run(&self, core: &CoreUnit) -> HashSet<Result> {
        let mut results: HashSet<Result> = HashSet::new();
        let compilation_units = core.get_compilation_units();

        for compilation_unit in compilation_units {
            // Key the storage variable read - Value the functions name where it's read
            let mut vars_read: HashMap<String, HashSet<String>> = HashMap::new();

            for f in compilation_unit
                .functions_user_defined()
                .filter(|f| f.ty() == &Type::View)
            {
                // With inlining avoided the view entrypoint is a `__wrapper__*`
                // whose reads happen in the Private user function it calls, so
                // collect reads transitively through user-defined callees.
                let mut visited: HashSet<String> = HashSet::new();
                Self::collect_view_reads(
                    compilation_unit,
                    f,
                    &f.name(),
                    &mut vars_read,
                    &mut visited,
                );
            }

            for f in compilation_unit.functions_user_defined() {
                for bb_info in f.analyses().reentrancy.iter() {
                    if let AnalysisState {
                        post: ReentrancyDomain::State(reentrancy_info),
                        ..
                    } = bb_info.1
                    {
                        for call in reentrancy_info.external_calls.iter() {
                            let external_function_call = statement_summary_in_named_function(
                                compilation_unit,
                                call.get_function(),
                                call.get_function_call().unwrap().get_statement(),
                            );

                            if is_safe_external_call(call, f.get_statements(), core) {
                                continue;
                            }

                            for written_variable in reentrancy_info.storage_variables_written.iter()
                            {
                                // The write may live in another function than
                                // `f` (recorded through private-call recursion),
                                // so trace it within its owning function's
                                // statements.
                                let written_variable_name = compilation_unit
                                    .functions()
                                    .find(|owner| owner.name() == written_variable.get_function())
                                    .and_then(|owner| {
                                        storage_statement_identity(
                                            written_variable
                                                .get_storage_variable_written()
                                                .as_ref()
                                                .unwrap()
                                                .get_statement(),
                                            owner.get_statements(),
                                        )
                                    })
                                    .unwrap_or_default();

                                let write_summary = statement_summary_in_named_function(
                                    compilation_unit,
                                    written_variable.get_function(),
                                    written_variable
                                        .get_storage_variable_written()
                                        .as_ref()
                                        .unwrap()
                                        .get_statement(),
                                );
                                let variable = storage_identity_pretty(&written_variable_name)
                                    .unwrap_or_else(|| "Variable".to_string());

                                for (read_variable_name, view_functions) in vars_read.iter() {
                                    // Precise match when both identities are
                                    // known; wildcard when either side is
                                    // unknown (prefer over-reporting to losing
                                    // the finding).
                                    if !written_variable_name.is_empty()
                                        && !read_variable_name.is_empty()
                                        && *read_variable_name != written_variable_name
                                    {
                                        continue;
                                    }
                                    for view_function in view_functions {
                                        results.insert(Result {
                                            name: self.name().to_string(),
                                            impact: self.impact(),
                                            confidence: self.confidence(),
                                            message: format!(
                                                "Read only reentrancy in {}\n\tExternal call to {} done in {}\n\t{} written after the call by {} in {}.",
                                                view_function,
                                                external_function_call,
                                                call.get_function(),
                                                variable,
                                                write_summary,
                                                written_variable.get_function(),
                                            ),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        results
    }
}

impl ReadOnlyReentrancy {
    /// Record the storage variables read by `current` (attributed to the view
    /// entrypoint `view_name`), then recurse into the user-defined functions
    /// it calls. Identities are computed against the owning function's
    /// statements; an empty string means the variable couldn't be identified
    /// and is treated as a wildcard match rather than dropping the read.
    fn collect_view_reads(
        compilation_unit: &crate::core::compilation_unit::CompilationUnit,
        current: &Function,
        view_name: &str,
        vars_read: &mut HashMap<String, HashSet<String>>,
        visited: &mut HashSet<String>,
    ) {
        if !visited.insert(current.name()) {
            return;
        }

        for storage_var_read in current.storage_vars_read() {
            let var_read = storage_statement_identity(storage_var_read, current.get_statements())
                .unwrap_or_default();
            vars_read
                .entry(var_read)
                .or_default()
                .insert(view_name.to_string());
        }

        for call in current
            .private_functions_calls()
            .chain(current.loop_functions_calls())
        {
            if let cairo_lang_sierra::program::GenStatement::Invocation(invoc) = call {
                if let Some(callee) = invoc
                    .libfunc_id
                    .debug_name
                    .as_ref()
                    .and_then(|n| n.strip_prefix("function_call<user@"))
                    .and_then(|n| n.strip_suffix('>'))
                {
                    if let Some(callee_function) = compilation_unit.function_by_name(callee) {
                        Self::collect_view_reads(
                            compilation_unit,
                            callee_function,
                            view_name,
                            vars_read,
                            visited,
                        );
                    }
                }
            }
        }
    }
}

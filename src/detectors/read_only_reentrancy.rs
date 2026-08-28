use super::detector::{Confidence, Detector, Impact, Result};
use crate::analysis::dataflow::AnalysisState;
use crate::analysis::reentrancy::ReentrancyDomain;
use crate::core::core_unit::CoreUnit;
use crate::core::function::Type;
use crate::utils::{is_safe_syscall, storage_statement_identity};
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
                for storage_var_read in f.storage_vars_read() {
                    // Empty string when the variable couldn't be identified —
                    // treated as a wildcard match below rather than dropping
                    // the read on the floor.
                    let var_read = storage_statement_identity(storage_var_read, f.get_statements())
                        .unwrap_or_default();
                    let functions_name = vars_read.entry(var_read).or_default();
                    functions_name.insert(f.name());
                }
            }

            for f in compilation_unit.functions_user_defined() {
                for bb_info in f.analyses().reentrancy.iter() {
                    if let AnalysisState {
                        post: ReentrancyDomain::State(reentrancy_info),
                        ..
                    } = bb_info.1
                    {
                        for call in reentrancy_info.external_calls.iter() {
                            let external_function_call =
                                format!("{}", call.get_function_call().unwrap().get_statement());

                            if let Some(safe_selectors) = core.get_safe_external_selectors() {
                                if is_safe_syscall(call, f.get_statements(), safe_selectors) {
                                    continue;
                                }
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
                                                "Read only reentrancy in {}\n\tExternal call {} done in {}\n\tVariable written after {} in {}",
                                                view_function,
                                                external_function_call,
                                                call.get_function(),
                                                written_variable
                                                    .get_storage_variable_written()
                                                    .as_ref()
                                                    .unwrap()
                                                    .get_statement(),
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

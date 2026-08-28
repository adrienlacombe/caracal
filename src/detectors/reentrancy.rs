use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::analysis::dataflow::AnalysisState;
use crate::analysis::reentrancy::ReentrancyDomain;
use crate::core::core_unit::CoreUnit;
use crate::utils::{
    is_safe_external_call, statement_summary_in_named_function, storage_identity_pretty,
    storage_variable_identity,
};

#[derive(Default)]
pub struct Reentrancy;

impl Detector for Reentrancy {
    fn name(&self) -> &str {
        "reentrancy"
    }

    fn description(&self) -> &str {
        "Detect when a storage variable is read before an external call and written after"
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

                            if let Some(current_vars_read_before_call) = reentrancy_info
                                .variables_read_before_calls
                                .iter()
                                .find(|entry| entry.0.get_id() == call.get_id())
                            {
                                let vars_read: Vec<String> = current_vars_read_before_call
                                    .1
                                    .iter()
                                    .map(|var| {
                                        storage_variable_identity(
                                            compilation_unit,
                                            var.get_function(),
                                            var.get_storage_variable_read()
                                                .as_ref()
                                                .unwrap()
                                                .get_statement(),
                                        )
                                    })
                                    .collect();
                                for written_variable in
                                    reentrancy_info.storage_variables_written.iter()
                                {
                                    let written_variable_name = storage_variable_identity(
                                        compilation_unit,
                                        written_variable.get_function(),
                                        written_variable
                                            .get_storage_variable_written()
                                            .as_ref()
                                            .unwrap()
                                            .get_statement(),
                                    );
                                    // Precise match when both identities are
                                    // known; wildcard when either side is
                                    // unknown (prefer over-reporting to losing
                                    // the finding).
                                    let read_before_call = vars_read.iter().any(|read| {
                                        read.is_empty()
                                            || written_variable_name.is_empty()
                                            || *read == written_variable_name
                                    });
                                    if read_before_call {
                                        let write_summary = statement_summary_in_named_function(
                                            compilation_unit,
                                            written_variable.get_function(),
                                            written_variable
                                                .get_storage_variable_written()
                                                .as_ref()
                                                .unwrap()
                                                .get_statement(),
                                        );
                                        let variable =
                                            storage_identity_pretty(&written_variable_name)
                                                .unwrap_or_else(|| "Variable".to_string());
                                        results.insert(Result {
                                            name: self.name().to_string(),
                                            impact: self.impact(),
                                            confidence: self.confidence(),
                                            message: format!(
                                                "Reentrancy in {}\n\tExternal call to {} done in {}\n\t{} written after the call by {} in {}.",
                                                f.name(),
                                                external_function_call,
                                                call.get_function(),
                                                variable,
                                                write_summary,
                                                written_variable.get_function()
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

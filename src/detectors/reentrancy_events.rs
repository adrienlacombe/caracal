use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::analysis::dataflow::AnalysisState;
use crate::analysis::reentrancy::ReentrancyDomain;
use crate::core::core_unit::CoreUnit;
use crate::utils::{is_safe_external_call, statement_summary_in_named_function};

#[derive(Default)]
pub struct ReentrancyEvents;

impl Detector for ReentrancyEvents {
    fn name(&self) -> &str {
        "reentrancy-events"
    }

    fn description(&self) -> &str {
        "Detect when an event is emitted after an external call leading to out-of-order events"
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

        for compilation_unit in compilation_units {
            for f in compilation_unit.functions_user_defined() {
                for bb_info in f.analyses().reentrancy.iter() {
                    if let AnalysisState {
                        post: ReentrancyDomain::State(reentrancy_info),
                        ..
                    } = bb_info.1
                    {
                        for event in reentrancy_info.events.iter() {
                            for call in reentrancy_info.external_calls.iter() {
                                // The event had already been emitted when this
                                // call was made (ordering snapshot taken at
                                // call registration) — not "emitted after the
                                // call".
                                if reentrancy_info
                                    .events_before_calls
                                    .get(call)
                                    .is_some_and(|events| events.contains(event))
                                {
                                    continue;
                                }
                                let external_function_call = statement_summary_in_named_function(
                                    compilation_unit,
                                    call.get_function(),
                                    call.get_function_call().unwrap().get_statement(),
                                );

                                if is_safe_external_call(call, f.get_statements(), core) {
                                    continue;
                                }

                                let event_summary = statement_summary_in_named_function(
                                    compilation_unit,
                                    event.get_function(),
                                    event.get_event_emitted().as_ref().unwrap().get_statement(),
                                );
                                results.insert(Result {
                                    name: self.name().to_string(),
                                    impact: self.impact(),
                                    confidence: self.confidence(),
                                    message: format!(
                                        "Reentrancy in {}\n\tExternal call to {} done in {}\n\tEvent emitted after the call by {} in {}.",
                                        f.name(),
                                        external_function_call,
                                        call.get_function(),
                                        event_summary,
                                        event.get_function()
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }

        results
    }
}

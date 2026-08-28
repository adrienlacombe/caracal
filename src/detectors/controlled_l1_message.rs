use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::core::core_unit::CoreUnit;
use crate::utils::{filter_builtins_from_arguments, statement_summary_in_named_function};
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::starknet::StarknetConcreteLibfunc;
use cairo_lang_sierra::program::Statement as SierraStatement;

/// `send_message_to_l1_syscall` with a user controlled `to_address` lets the
/// caller pick which L1 contract consumes the message. L1 bridges pattern
/// their consumption on (from_l2_address, to_address, payload), so a caller
/// who controls `to_address` can redirect value or spoof messages to an L1
/// consumer that trusts this contract. Only the destination address is
/// checked — the payload is expected to carry user data.
///
/// `send_message_to_l1_syscall` is declared `extern fn` in the corelib, so
/// it always lowers to the raw `send_message_to_l1_syscall` libfunc: in the
/// user's own named function when compiling with inlining avoided (caracal's
/// compilation), and inside the `__wrapper__*` entrypoint for pre-inlined
/// artifacts (the scarb path). There is no `FunctionCall` shape to match, so
/// the single raw-libfunc path covers both.
#[derive(Default)]
pub struct ControlledL1Message {}

impl Detector for ControlledL1Message {
    fn name(&self) -> &str {
        "controlled-l1-message"
    }

    fn description(&self) -> &str {
        "Detect send_message_to_l1_syscall with a user controlled to_address"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn impact(&self) -> Impact {
        Impact::Medium
    }

    fn run(&self, core: &CoreUnit) -> HashSet<Result> {
        let mut results: HashSet<Result> = HashSet::new();

        for compilation_unit in core.get_compilation_units() {
            for f in compilation_unit.functions_user_defined() {
                for stmt in f.get_statements().iter() {
                    let SierraStatement::Invocation(invoc) = stmt else {
                        continue;
                    };
                    let libfunc = compilation_unit
                        .registry()
                        .get_libfunc(&invoc.libfunc_id)
                        .expect("Library function not found in the registry");

                    let CoreConcreteLibfunc::Starknet(StarknetConcreteLibfunc::SendMessageToL1(s)) =
                        libfunc
                    else {
                        continue;
                    };

                    // The sierra signature of send_message_to_l1_syscall is
                    // (GasBuiltin, System, felt252 to_address,
                    // Span<felt252> payload) -> SyscallResult<()>.
                    // Strip builtins; the first remaining formal is the
                    // destination address.
                    let user_args = filter_builtins_from_arguments(
                        &s.signature.param_signatures,
                        invoc.args.clone(),
                    );
                    let Some(to_address) = user_args.into_iter().next() else {
                        continue;
                    };

                    if compilation_unit.is_tainted(f.name(), to_address) {
                        results.insert(Result {
                            name: self.name().to_string(),
                            impact: self.impact(),
                            confidence: self.confidence(),
                            message: format!(
                                "send_message_to_l1_syscall with user controlled to_address in {}\n {}",
                                f.name(),
                                statement_summary_in_named_function(compilation_unit, &f.name(), stmt)
                            ),
                        });
                    }
                }
            }
        }

        results
    }
}

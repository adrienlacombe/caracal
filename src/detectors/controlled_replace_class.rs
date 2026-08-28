use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::core::core_unit::CoreUnit;
use crate::utils::{filter_builtins_from_arguments, statement_summary_in_named_function};
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::starknet::StarknetConcreteLibfunc;
use cairo_lang_sierra::program::Statement as SierraStatement;

/// `replace_class_syscall` overwrites the contract's own class — there is no
/// undo. If any user-reachable path can invoke it with a class hash that was
/// derived from the entrypoint's calldata (directly or through a private
/// helper), an attacker can brick the contract or install malicious code.
///
/// The check mirrors `controlled_library_call` but targets the upgrade path:
/// the impact is higher because the side effect persists across transactions
/// instead of being scoped to a single call.
#[derive(Default)]
pub struct ControlledReplaceClass {}

impl Detector for ControlledReplaceClass {
    fn name(&self) -> &str {
        "controlled-replace-class"
    }

    fn description(&self) -> &str {
        "Detect replace_class_syscall with a user controlled class hash"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn impact(&self) -> Impact {
        Impact::High
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

                    let CoreConcreteLibfunc::Starknet(StarknetConcreteLibfunc::ReplaceClass(rc)) =
                        libfunc
                    else {
                        continue;
                    };

                    // The sierra signature of replace_class_syscall is
                    // (GasBuiltin, System, ClassHash) -> SyscallResult<()>.
                    // Strip builtins; the single remaining formal is the
                    // class hash we care about.
                    let user_args = filter_builtins_from_arguments(
                        &rc.signature.param_signatures,
                        invoc.args.clone(),
                    );
                    let Some(class_hash) = user_args.into_iter().next() else {
                        continue;
                    };

                    if compilation_unit.is_tainted(f.name(), class_hash) {
                        results.insert(Result {
                            name: self.name().to_string(),
                            impact: self.impact(),
                            confidence: self.confidence(),
                            message: format!(
                                "replace_class_syscall with user controlled class hash in {}\n {}",
                                f.name(),
                                statement_summary_in_named_function(
                                    compilation_unit,
                                    &f.name(),
                                    stmt
                                )
                            ),
                        });
                    }
                }
            }
        }

        results
    }
}

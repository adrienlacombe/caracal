use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::core::core_unit::CoreUnit;
use crate::utils::{filter_builtins_from_arguments, statement_summary_in_named_function};
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::starknet::StarknetConcreteLibfunc;
use cairo_lang_sierra::program::Statement as SierraStatement;

/// `deploy_syscall` with a user controlled class hash lets the caller choose
/// the code of the deployed contract: anything that trusts the deployed
/// address afterwards (registries, callbacks, accounting) can be pointed at
/// malicious code. Only the class hash argument is checked — a user
/// controlled salt influences the deployed address, not the code, and is not
/// worth flagging on its own.
///
/// `deploy_syscall` is declared `extern fn` in the corelib, so it always
/// lowers to the raw `deploy_syscall` libfunc: in the user's own named
/// function when compiling with inlining avoided (caracal's compilation),
/// and inside the `__wrapper__*` entrypoint for pre-inlined artifacts (the
/// scarb path). Unlike dispatcher-based calls there is no `FunctionCall`
/// shape to match, so the single raw-libfunc path covers both.
#[derive(Default)]
pub struct ControlledDeploy {}

impl Detector for ControlledDeploy {
    fn name(&self) -> &str {
        "controlled-deploy"
    }

    fn description(&self) -> &str {
        "Detect deploy_syscall with a user controlled class hash"
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

                    let CoreConcreteLibfunc::Starknet(StarknetConcreteLibfunc::Deploy(d)) = libfunc
                    else {
                        continue;
                    };

                    // The sierra signature of deploy_syscall is
                    // (GasBuiltin, System, ClassHash, felt252 salt,
                    // Span<felt252> calldata, bool deploy_from_zero)
                    // -> SyscallResult<(ContractAddress, Span<felt252>)>.
                    // Strip builtins; the first remaining formal is the
                    // class hash.
                    let user_args = filter_builtins_from_arguments(
                        &d.signature.param_signatures,
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
                                "deploy_syscall with user controlled class hash in {}\n {}",
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

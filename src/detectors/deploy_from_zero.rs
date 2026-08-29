use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::core::core_unit::CoreUnit;
use crate::utils::{statement_locations, statement_summary_in_named_function, trace_const_bool};
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::starknet::StarknetConcreteLibfunc;
use cairo_lang_sierra::program::Statement as SierraStatement;

/// `deploy_syscall` with `deploy_from_zero = true` computes the deployed
/// address without the deployer's address in the hash, so the address is the
/// same for anyone who deploys that (class hash, salt, calldata) tuple.
/// Another party can front-run the deployment (address squatting) or grief
/// it: a second deploy-from-zero of the same tuple collides and reverts.
/// Unless the contract deliberately implements a cross-deployer singleton
/// pattern, the flag should be false.
///
/// The flag is the last argument of the syscall — a `core::bool` that is
/// almost always a literal. It is traced back to its constant producer
/// (`utils::trace_const_bool`); when the value is not statically
/// determinable the call is not flagged (under-reporting is preferred over
/// guessing). Like `controlled-deploy`, the raw-libfunc match covers both
/// caracal's own compilation and pre-inlined artifacts because
/// `deploy_syscall` is an `extern fn` that never lowers to a `FunctionCall`.
#[derive(Default)]
pub struct DeployFromZero {}

impl Detector for DeployFromZero {
    fn name(&self) -> &str {
        "deploy-from-zero"
    }

    fn description(&self) -> &str {
        "Detect deploy_syscall with the deploy_from_zero flag enabled"
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

                    if !matches!(
                        libfunc,
                        CoreConcreteLibfunc::Starknet(StarknetConcreteLibfunc::Deploy(_))
                    ) {
                        continue;
                    }

                    // The sierra signature of deploy_syscall is
                    // (GasBuiltin, System, ClassHash, felt252 salt,
                    // Span<felt252> calldata, bool deploy_from_zero): the
                    // flag is the last argument.
                    let Some(flag) = invoc.args.last() else {
                        continue;
                    };

                    if trace_const_bool(f.get_statements(), flag.id) == Some(true) {
                        results.insert(Result {
                            name: self.name().to_string(),
                            impact: self.impact(),
                            confidence: self.confidence(),
                            message: format!(
                                "deploy_syscall with deploy_from_zero enabled in {}\n {}",
                                f.name(),
                                statement_summary_in_named_function(
                                    compilation_unit,
                                    &f.name(),
                                    stmt
                                )
                            ),
                            locations: statement_locations(compilation_unit, &f.name(), stmt),
                        });
                    }
                }
            }
        }

        results
    }
}

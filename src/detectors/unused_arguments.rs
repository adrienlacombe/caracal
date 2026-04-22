use super::detector::{Confidence, Detector, Impact, Result};
use crate::core::core_unit::CoreUnit;
use crate::utils::number_to_ordinal;
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::program::Statement as SierraStatement;
use std::collections::HashSet;

// Historical context: this detector looked for a `Drop<T>` libfunc as the very
// first invocation of a user function — the compiler's old way of signalling
// "this formal parameter was never read". Since cairo 2.6 entrypoints are
// inlined into a compiler-generated `__wrapper__*` whose only non-builtin
// parameter is a `Span<felt252>` of raw calldata. The user's declared
// arguments (`a`, `b`, …) no longer exist as first-class sierra params; they
// are synthesized by the inlined `Serde::deserialize` loop, and their unused-
// ness is not observable from the `Drop` position anymore. The detector
// therefore currently reports nothing on modern cairo; restoring it would
// require parsing the ABI and tracking which deserialized calldata slots are
// actually consumed. Left in place so the behaviour is deliberate rather than
// accidentally removed.
#[derive(Default)]
pub struct UnusedArguments {}

impl Detector for UnusedArguments {
    fn name(&self) -> &str {
        "unused-arguments"
    }

    fn description(&self) -> &str {
        "Detect unused arguments"
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
                // Calculate the offset to subtract from the paramter id. Builtins arguments are always before the user defined.
                let offset = f.params_all().count() - f.params().count();

                for stmt in f.get_statements() {
                    if let SierraStatement::Invocation(invoc) = stmt {
                        // Get the concrete libfunc called
                        let libfunc = compilation_unit
                            .registry()
                            .get_libfunc(&invoc.libfunc_id)
                            .expect("Library function not found in the registry");

                        // If an argument is unused there is a Drop as the first instruction
                        // When we don't have any more Drop instructions we are sure the others are used
                        if let CoreConcreteLibfunc::Drop(drop_libfunc) = libfunc {
                            // We don't report if self (the first argument) is unused
                            // NOTE: as of now the compiler allows to use a ContractState argument everywhere
                            if !drop_libfunc.signature.param_signatures[0]
                                .ty
                                .debug_name
                                .as_ref()
                                .unwrap()
                                .as_str()
                                .ends_with("::ContractState")
                            {
                                results.insert(Result {
                                    name: self.name().to_string(),
                                    impact: self.impact(),
                                    confidence: self.confidence(),
                                    message: format!(
                                        "The {} argument in {} is never used",
                                        number_to_ordinal(invoc.args[0].id - offset as u64 + 1),
                                        f.name()
                                    ),
                                });
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        results
    }
}

use super::detector::{Confidence, Detector, Impact, Result};
use crate::core::core_unit::CoreUnit;
use crate::utils::{function_summary, number_to_ordinal};
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::program::Statement as SierraStatement;
use std::collections::HashSet;

// This detector looks for `Drop<T>` libfuncs as the leading invocations of a
// user function — the compiler's way of signalling "this formal parameter was
// never read". It requires the user function to exist as its own sierra
// function with its declared parameters. Caracal compiles with inlining
// avoided, which keeps entrypoint bodies as separate Private functions called
// from the `__wrapper__*`, so the detector works again on cairo >= 2.6 (it
// had been inert between commit 61488ce and the inlining-avoid change: the
// inlined wrapper's only data parameter was the raw `Span<felt252>` calldata
// and the unused-ness of the deserialized arguments was not observable from
// the `Drop` position). It remains inert on sierra produced with default
// inlining, e.g. pre-built scarb artifacts.
//
// Scope: user-declared value arguments of user-written, non-generic
// functions. The inlining-avoid compilation also keeps a lot of code the
// contract author never wrote as Private sierra functions, and reporting
// their intentionally-ignored parameters is pure noise. Skipped by name/type
// shape:
// - functions with a turbofish (`::<`) in their path: monomorphized generic
//   functions — library-provided default/hook impls (`ERC20HooksEmptyImpl`,
//   `ERC4626DefaultNoFees`, ...), derived impls, and macro plumbing
//   (`ComponentStateDeref::<...>::deref`) instantiated for this contract; the
//   signature is fixed by the generic trait, not by the contract author;
// - compiler-generated closure wrappers (`{closure@...}` in the path): the
//   flagged parameter is the wrapper's closure struct, not a user argument.
//   No fixture covers this class — closure debug names embed the absolute
//   source path, which would make the snapshot machine-specific — but on the
//   OpenZeppelin corpus every such finding pointed at the wrapper plumbing;
// - an unused `self` when its type is the contract/component state (value or
//   snapshot): the compiler requires the parameter, ignoring it is normal
//   (stateless helpers, trait-mandated receivers like `HasComponentImpl_*::
//   get_contract` or a mock's constant-returning trait methods);
// - empty functions (the body does nothing at all): stubs and hook
//   conformances — most notably a hooks-trait method the impl did not
//   override, whose empty *default* body from the trait declaration is
//   materialized under the impl's own concrete path
//   (`MyContract::ERC721HooksImpl::after_update`) as if the user wrote it.
#[derive(Default)]
pub struct UnusedArguments {}

/// True when `ty` is a contract/component state type or a snapshot of one —
/// the shape of a `self` parameter, whose unused-ness is not worth reporting.
fn is_state_type(ty: &str) -> bool {
    let inner = ty
        .strip_prefix("Snapshot<")
        .and_then(|t| t.strip_suffix('>'))
        .unwrap_or(ty);
    inner.ends_with("::ContractState")
        || inner.ends_with("::ComponentState")
        || inner.contains("::ComponentState::<")
}

/// True when the function body does nothing: every statement is a drop of an
/// argument, a unit (empty-struct) construction, pure value plumbing
/// (store_temp & co), or the return. Such a function is a stub or a hook
/// conformance whose arguments are ignored by design, not by accident.
fn is_empty_function(
    f: &crate::core::function::Function,
    compilation_unit: &crate::core::compilation_unit::CompilationUnit,
) -> bool {
    use cairo_lang_sierra::extensions::structure::StructConcreteLibfunc;

    f.get_statements().iter().all(|stmt| match stmt {
        SierraStatement::Invocation(invoc) => {
            let libfunc = compilation_unit
                .registry()
                .get_libfunc(&invoc.libfunc_id)
                .expect("Library function not found in the registry");
            match libfunc {
                CoreConcreteLibfunc::Drop(_) | CoreConcreteLibfunc::Mem(_) => true,
                CoreConcreteLibfunc::Struct(StructConcreteLibfunc::Construct(_)) => {
                    // Only the construction of an empty struct — the unit
                    // return value — qualifies as "nothing".
                    invoc.args.is_empty()
                }
                _ => false,
            }
        }
        SierraStatement::Return(_) => true,
    })
}

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
                let name = f.name();
                // Not user-written code — see the scope note on the struct.
                if name.contains("::<") || name.contains("{closure@") {
                    continue;
                }

                // Empty stub/hook — its arguments are ignored by design.
                if is_empty_function(f, compilation_unit) {
                    continue;
                }

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
                            // We don't report if self is unused: the state
                            // parameter (contract or component, value or
                            // snapshot) is required by the compiler whether or
                            // not the body touches it.
                            if !is_state_type(
                                drop_libfunc.signature.param_signatures[0]
                                    .ty
                                    .debug_name
                                    .as_ref()
                                    .unwrap()
                                    .as_str(),
                            ) {
                                results.insert(Result {
                                    name: self.name().to_string(),
                                    impact: self.impact(),
                                    confidence: self.confidence(),
                                    message: format!(
                                        "The {} argument in {} is never used",
                                        number_to_ordinal(invoc.args[0].id - offset as u64 + 1),
                                        function_summary(compilation_unit, &f.name())
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

use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::core::compilation_unit::CompilationUnit;
use crate::core::core_unit::CoreUnit;
use crate::core::function::Type;
use crate::utils::{skip_bookkeeping, statement_summary_in_named_function};
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::enm::EnumConcreteLibfunc;
use cairo_lang_sierra::extensions::structure::StructConcreteLibfunc;
use cairo_lang_sierra::extensions::ConcreteType;
use cairo_lang_sierra::program::Statement as SierraStatement;

/// Some ERC20 implementations return `false` on a failed `transfer` /
/// `transfer_from` instead of reverting. Dropping the returned bool means a
/// failed token movement goes unnoticed while the surrounding logic
/// (accounting, unlocks, mints) proceeds as if it had succeeded — a classic
/// unchecked-transfer bug worth more severity than a generic unused return.
///
/// Detection is the `unused-return` dropped-return pattern restricted to
/// `FunctionCall` statements whose callee is a contract dispatcher method
/// (`Type::AbiCallContract`) named `transfer`, `transfer_from` or
/// `transferFrom`. Like `unused-return` this only sees calls that survive in
/// the sierra: with inlining avoided (caracal's compilation) all dispatcher
/// calls do; sierra produced with default aggressive inlining may lose them.
#[derive(Default)]
pub struct UncheckedTransfer;

/// Final path segment of a dispatcher method path, generic arguments
/// stripped: `pkg::IERC20DispatcherImpl::transfer` -> `transfer`.
fn method_name(callee: &str) -> &str {
    let base = callee.split("::<").next().unwrap_or(callee);
    let last = base.rsplit("::").next().unwrap_or(base);
    last.split('<').next().unwrap_or(last)
}

fn is_transfer_method(callee: &str) -> bool {
    matches!(
        method_name(callee),
        "transfer" | "transfer_from" | "transferFrom"
    )
}

impl Detector for UncheckedTransfer {
    fn name(&self) -> &str {
        "unchecked-transfer"
    }

    fn description(&self) -> &str {
        "Detect ERC20 transfer/transfer_from calls whose returned bool is ignored"
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
                for (i, stmt) in f.get_statements().iter().enumerate() {
                    let SierraStatement::Invocation(invoc) = stmt else {
                        continue;
                    };
                    let libfunc = compilation_unit
                        .registry()
                        .get_libfunc(&invoc.libfunc_id)
                        .expect("Library function not found in the registry");
                    let CoreConcreteLibfunc::FunctionCall(f_called) = libfunc else {
                        continue;
                    };

                    let callee_name = f_called.function.id.debug_name.as_ref().unwrap().as_str();
                    if !is_transfer_method(callee_name) {
                        continue;
                    }
                    // Only dispatcher methods of an ABI trait that perform a
                    // contract call — not user functions that happen to be
                    // named transfer.
                    let is_dispatcher = compilation_unit
                        .function_by_name(callee_name)
                        .is_some_and(|callee| *callee.ty() == Type::AbiCallContract);
                    if !is_dispatcher {
                        continue;
                    }

                    let ret_vars = &invoc.branches[0].results;
                    let following = skip_bookkeeping(f.get_statements_at(i + 1));
                    if self.is_return_dropped(compilation_unit, following, ret_vars) {
                        results.insert(Result {
                            name: self.name().to_string(),
                            impact: self.impact(),
                            confidence: self.confidence(),
                            message: format!(
                                "The return value of the ERC20 transfer call to {} is never checked in {}",
                                statement_summary_in_named_function(compilation_unit, &f.name(), stmt),
                                f.name()
                            ),
                        });
                    }
                }
            }
        }

        results
    }
}

impl UncheckedTransfer {
    /// True when the dispatcher call's return value is dropped without being
    /// looked at. The shapes mirror `unused-return`: an immediate `drop`, or
    /// an `enum_match` on the `PanicResult` / `struct_deconstruct` of the
    /// payload tuple followed (modulo bookkeeping) by a `drop`. The first
    /// statement must consume one of the call's results so unrelated cleanup
    /// interleaved by the compiler isn't misread as the drop.
    fn is_return_dropped(
        &self,
        compilation_unit: &CompilationUnit,
        stmts: &[SierraStatement],
        ret_vars: &[cairo_lang_sierra::ids::VarId],
    ) -> bool {
        let Some(SierraStatement::Invocation(invoc)) = stmts.first() else {
            return false;
        };
        if !invoc.args.iter().any(|a| ret_vars.contains(a)) {
            return false;
        }
        let libfunc = compilation_unit
            .registry()
            .get_libfunc(&invoc.libfunc_id)
            .expect("Library function not found in the registry");

        match libfunc {
            CoreConcreteLibfunc::Drop(drop_libfunc) => !self.is_zero_sized(
                compilation_unit,
                &drop_libfunc.signature.param_signatures[0].ty,
            ),
            CoreConcreteLibfunc::Enum(EnumConcreteLibfunc::Match(_))
            | CoreConcreteLibfunc::Struct(StructConcreteLibfunc::Deconstruct(_)) => {
                // Follow the success-branch unwrapping; a short bounded walk
                // is enough since the dispatcher returns a single bool.
                let mut rest = skip_bookkeeping(&stmts[1..]);
                for _ in 0..4 {
                    let Some(SierraStatement::Invocation(inner)) = rest.first() else {
                        return false;
                    };
                    let inner_libfunc = compilation_unit
                        .registry()
                        .get_libfunc(&inner.libfunc_id)
                        .expect("Library function not found in the registry");
                    match inner_libfunc {
                        CoreConcreteLibfunc::Drop(drop_libfunc) => {
                            return !self.is_zero_sized(
                                compilation_unit,
                                &drop_libfunc.signature.param_signatures[0].ty,
                            );
                        }
                        CoreConcreteLibfunc::Struct(StructConcreteLibfunc::Deconstruct(_)) => {
                            rest = skip_bookkeeping(&rest[1..]);
                        }
                        _ => return false,
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn is_zero_sized(
        &self,
        compilation_unit: &CompilationUnit,
        ty: &cairo_lang_sierra::ids::ConcreteTypeId,
    ) -> bool {
        compilation_unit
            .registry()
            .get_type(ty)
            .expect("Type not found in registry")
            .info()
            .zero_sized
    }
}

use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::core::compilation_unit::CompilationUnit;
use crate::core::core_unit::CoreUnit;
use crate::core::function::Type;
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::enm::EnumConcreteLibfunc;
use cairo_lang_sierra::extensions::structure::StructConcreteLibfunc;
use cairo_lang_sierra::extensions::ConcreteType;
use cairo_lang_sierra::program::{GenStatement, Statement as SierraStatement, StatementIdx};

// Scope on cairo >= 2.6: this detector inspects `function_call` statements,
// so it only sees calls that survive the compiler's inlining. Small private
// functions — the typical "called and result ignored" case — are inlined into
// the `__wrapper__*` entrypoint and the unused computation is then deleted
// outright, leaving no trace in sierra to detect. The detector still works
// (and is tested) on calls the inliner keeps as real call boundaries:
// `#[inline(never)]` functions, and functions the inliner rejects (recursive
// or large bodies). Restoring coverage of the inlined case is not possible at
// the sierra level — the information no longer exists.
#[derive(Default)]
pub struct UnusedReturn;

/// Skip leading statements that are pure bookkeeping — no data arguments, no
/// results — so they can't affect whether a return value is used. The
/// compiler freely interleaves these with the drop/deconstruct sequence this
/// detector pattern-matches (e.g. a `disable_ap_tracking` between the
/// `branch_align` and the `drop` on cairo >= 2.6).
fn skip_bookkeeping(mut stmts: &[SierraStatement]) -> &[SierraStatement] {
    while let Some(SierraStatement::Invocation(invoc)) = stmts.first() {
        let is_bookkeeping = invoc.libfunc_id.debug_name.as_ref().is_some_and(|n| {
            n == "branch_align" || n == "disable_ap_tracking" || n == "enable_ap_tracking"
        });
        if !is_bookkeeping {
            break;
        }
        stmts = &stmts[1..];
    }
    stmts
}

impl Detector for UnusedReturn {
    fn name(&self) -> &str {
        "unused-return"
    }

    fn description(&self) -> &str {
        "Detect unused return values"
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
                for (i, stmt) in f.get_statements().iter().enumerate() {
                    if let SierraStatement::Invocation(invoc) = stmt {
                        // Get the return values from the function
                        let ret_vars = &invoc.branches[0].results;
                        // Get the concrete libfunc called
                        let libfunc = compilation_unit
                            .registry()
                            .get_libfunc(&invoc.libfunc_id)
                            .expect("Library function not found in the registry");

                        if let CoreConcreteLibfunc::FunctionCall(f_called) = libfunc {
                            // Get the statements after the function call
                            // if it's a drop it means there is an unused argument
                            // if it's a struct_deconstruct we need to look at the next statement until it's different from struct_deconstruct
                            // and check if it's a drop
                            // if it's a enum_match we will have something like that
                            //    function_call<user@unused_result::unused_result::UnusedResult::add_1>([6], [7], [8]) -> ([3], [4], [5]);
                            //    enum_match<core::PanicResult::<(core::felt252,)>>([5]) { fallthrough([9]) 63([10]) };
                            //    branch_align() -> ();
                            //    struct_deconstruct<Tuple<felt252>>([9]) -> ([11]);
                            // followed possibly by others struct_deconstruct and eventually a drop
                            // Note: we should avoid report when a Unit () is dropped

                            if let Some(f) = compilation_unit.functions().find(|f| {
                                f.name() == f_called.function.id.debug_name.clone().unwrap()
                            }) {
                                // We don't check for unused return in case of Storage functions
                                // When a loop function is called in sierra and in that function
                                // an array is emptied with pop_front this array is dropped
                                // when returning from the function call and it would be incorrectly
                                // reported as unused-return
                                if matches!(f.ty(), &Type::Storage | &Type::Loop) {
                                    continue;
                                }
                            } else {
                                // Should never happen
                                println!(
                                    "Unused-return: function not found {}",
                                    f_called.function.id.debug_name.clone().unwrap()
                                );
                                continue;
                            }

                            let following_stmts = skip_bookkeeping(f.get_statements_at(i + 1));
                            if let SierraStatement::Invocation(invoc) = &following_stmts[0] {
                                let mut libfunc = compilation_unit
                                    .registry()
                                    .get_libfunc(&invoc.libfunc_id)
                                    .expect("Library function not found in the registry");
                                // Get the parameters to the instruction for the struct_deconstruct case
                                let args = &invoc.args;
                                // Immediate Drop instruction
                                if let CoreConcreteLibfunc::Drop(drop_libfunc) = libfunc {
                                    let ty_dropped = compilation_unit
                                        .registry()
                                        .get_type(&drop_libfunc.signature.param_signatures[0].ty)
                                        .expect("Type not found in registry");
                                    let info = ty_dropped.info();
                                    // If size is 0 it's the Unit type
                                    if !info.zero_sized {
                                        results.insert(Result {
                                            name: self.name().to_string(),
                                            impact: self.impact(),
                                            confidence: self.confidence(),
                                            message: format!(
                                            "Return value unused for the function call {} in {}",
                                            stmt,
                                            f.name()
                                        ),
                                        });
                                    }
                                } else if let CoreConcreteLibfunc::Struct(
                                    StructConcreteLibfunc::Deconstruct(_),
                                ) = libfunc
                                {
                                    let return_variables = invoc.branches[0].results.len();

                                    // Go to the next statement and update the libfunc
                                    let stmt_to_check = skip_bookkeeping(&following_stmts[1..]);
                                    if let SierraStatement::Invocation(invoc) = &stmt_to_check[0] {
                                        libfunc = compilation_unit
                                            .registry()
                                            .get_libfunc(&invoc.libfunc_id)
                                            .expect("Library function not found in the registry");
                                        // We want to make sure the struct_deconstruct corresponds to the function's return values, and not any misc. struct cleanup
                                        if ret_vars.contains(&args[0]) {
                                            self.iterate_struct_deconstruct(
                                                compilation_unit,
                                                &mut results,
                                                libfunc,
                                                stmt_to_check,
                                                stmt,
                                                &f.name(),
                                                return_variables,
                                            );
                                        }
                                    }
                                } else if let CoreConcreteLibfunc::Enum(
                                    EnumConcreteLibfunc::Match(_),
                                ) = libfunc
                                {
                                    let return_variables = invoc.branches[0].results.len();
                                    // Skip the branch_align (and any ap-tracking
                                    // toggles) after the enum_match; the next
                                    // data statement is a struct_deconstruct or
                                    // a drop of the whole payload
                                    let stmt_to_check = skip_bookkeeping(&following_stmts[1..]);
                                    if let SierraStatement::Invocation(invoc) = &stmt_to_check[0] {
                                        libfunc = compilation_unit
                                            .registry()
                                            .get_libfunc(&invoc.libfunc_id)
                                            .expect("Library function not found in the registry");

                                        self.iterate_struct_deconstruct(
                                            compilation_unit,
                                            &mut results,
                                            libfunc,
                                            stmt_to_check,
                                            stmt,
                                            &f.name(),
                                            return_variables,
                                        );
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

impl<'a> UnusedReturn {
    #[allow(clippy::too_many_arguments)]
    fn iterate_struct_deconstruct(
        &self,
        compilation_unit: &'a CompilationUnit,
        results: &mut HashSet<Result>,
        mut libfunc: &'a CoreConcreteLibfunc,
        mut stmt_to_check: &[GenStatement<StatementIdx>],
        stmt: &GenStatement<StatementIdx>,
        function_name: &str,
        return_variables: usize,
    ) {
        let mut return_variables_counter = 0;
        while let CoreConcreteLibfunc::Struct(StructConcreteLibfunc::Deconstruct(_)) = libfunc {
            if let SierraStatement::Invocation(invoc) = &stmt_to_check[0] {
                libfunc = compilation_unit
                    .registry()
                    .get_libfunc(&invoc.libfunc_id)
                    .expect("Library function not found in the registry");

                // If there are other struct deconstruction are not related to the returned variables
                if return_variables_counter == return_variables {
                    break;
                }

                return_variables_counter += 1;

                stmt_to_check = skip_bookkeeping(&stmt_to_check[1..]);
            } else {
                break;
            }
        }

        // If the instruction after all the struct_deconstruct is a drop report unused return value
        if let CoreConcreteLibfunc::Drop(drop_libfunc) = libfunc {
            let ty_dropped = compilation_unit
                .registry()
                .get_type(&drop_libfunc.signature.param_signatures[0].ty)
                .expect("Type not found in registry");
            let info = ty_dropped.info();
            // If size is 0 it's the Unit type
            if !info.zero_sized {
                results.insert(Result {
                    name: self.name().to_string(),
                    impact: self.impact(),
                    confidence: self.confidence(),
                    message: format!(
                        "Return value unused for the function call {} in {}",
                        stmt, function_name
                    ),
                });
            }
        }
    }
}

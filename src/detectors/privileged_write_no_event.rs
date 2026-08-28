use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::core::core_unit::CoreUnit;
use crate::core::function::{Function, Type};
use crate::utils::{call_tree_any, function_locations, function_summary, is_caller_checked};
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::starknet::StarknetConcreteLibfunc;
use cairo_lang_sierra::program::Statement as SierraStatement;
use fxhash::FxHashSet;

/// An External entrypoint that is caller-gated (an access-controlled,
/// privileged operation) and writes storage should emit an event: privileged
/// configuration changes — owners, fees, implementations, limits — are
/// exactly what off-chain monitoring, indexers and users need to observe,
/// and a silent change is a common audit finding (and occasionally hides a
/// rug vector). Unprivileged writes are not flagged: user-facing state
/// churn (transfers, deposits) without events is a different, noisier
/// question.
///
/// Recognition: caller-gating reuses the shared `utils::is_caller_checked`;
/// storage writes and event emissions are collected over the entrypoint's
/// whole call tree (`Function::storage_vars_written` / `events_emitted`
/// cover the corelib accessor calls and the raw `storage_write_syscall`; raw
/// `emit_event_syscall` libfuncs are matched separately since the meta
/// information does not record them).
///
/// Impact and confidence are Low: this is an observability finding, the
/// gate heuristic counts any caller comparison as privilege, and events
/// emitted through unusual helpers may be missed.
#[derive(Default)]
pub struct PrivilegedWriteNoEvent {}

impl Detector for PrivilegedWriteNoEvent {
    fn name(&self) -> &str {
        "privileged-write-no-event"
    }

    fn description(&self) -> &str {
        "Detect caller-gated external functions that write storage without emitting an event"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn impact(&self) -> Impact {
        Impact::Low
    }

    fn run(&self, core: &CoreUnit) -> HashSet<Result> {
        let mut results: HashSet<Result> = HashSet::new();

        for compilation_unit in core.get_compilation_units() {
            for f in compilation_unit
                .functions()
                .filter(|f| *f.ty() == Type::External)
            {
                let mut visited = HashSet::new();
                if !call_tree_any(compilation_unit, f, &mut visited, &mut |callee| {
                    callee.storage_vars_written().next().is_some()
                }) {
                    continue;
                }

                let mut checked_functions = HashSet::new();
                if !is_caller_checked(
                    &FxHashSet::default(),
                    compilation_unit,
                    f,
                    &mut checked_functions,
                ) {
                    continue;
                }

                let mut visited = HashSet::new();
                let emits_event = call_tree_any(compilation_unit, f, &mut visited, &mut |callee| {
                    emits_event_locally(compilation_unit, callee)
                });
                if emits_event {
                    continue;
                }

                results.insert(Result {
                    name: self.name().to_string(),
                    impact: self.impact(),
                    confidence: self.confidence(),
                    message: format!(
                        "The caller-gated external function {} writes storage without emitting an event",
                        function_summary(compilation_unit, &f.name())
                    ),
                    locations: function_locations(compilation_unit, &f.name()),
                });
            }
        }

        results
    }
}

/// True when `function` itself emits an event: an emitter `FunctionCall`
/// (recorded in the meta information) or a raw `emit_event_syscall`
/// (pre-inlined artifacts).
fn emits_event_locally(
    compilation_unit: &crate::core::compilation_unit::CompilationUnit,
    function: &Function,
) -> bool {
    if function.events_emitted().next().is_some() {
        return true;
    }
    function.get_statements().iter().any(|stmt| {
        let SierraStatement::Invocation(invoc) = stmt else {
            return false;
        };
        let libfunc = compilation_unit
            .registry()
            .get_libfunc(&invoc.libfunc_id)
            .expect("Library function not found in the registry");
        matches!(
            libfunc,
            CoreConcreteLibfunc::Starknet(StarknetConcreteLibfunc::EmitEvent(_))
        )
    })
}

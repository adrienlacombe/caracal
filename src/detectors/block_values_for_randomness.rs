use std::collections::HashSet;

use super::detector::{Confidence, Detector, Impact, Result};
use crate::analysis::taint::WrapperVariable;
use crate::core::compilation_unit::CompilationUnit;
use crate::core::core_unit::CoreUnit;
use crate::core::function::Function;
use crate::utils::{
    filter_builtins_from_arguments, filter_builtins_from_returns, statement_locations,
    statement_summary_in_named_function,
};
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::structure::StructConcreteLibfunc;
use cairo_lang_sierra::extensions::ConcreteLibfunc;
use cairo_lang_sierra::program::{GenInvocation, Statement as SierraStatement, StatementIdx};
use rustc_hash::FxHashSet;

/// The block timestamp and block number are chosen by the sequencer (and
/// knowable by anyone before inclusion), so deriving "randomness" from them —
/// hashing them, or taking a modulo — is predictable and manipulable: the
/// classic weak-PRNG pattern. Plain comparisons are NOT flagged: using the
/// timestamp for deadlines or vesting checks is legitimate.
///
/// Sources are reads of the block values in both shapes: a `FunctionCall` to
/// `core::starknet::info::get_block_timestamp` / `get_block_number`
/// (inlining avoided) and the `struct_deconstruct<core::starknet::info::
/// BlockInfo>` a pre-inlined artifact boils those getters down to (member 0
/// is the number, member 1 the timestamp). Sinks are hash computations (raw
/// `pedersen` / `hades_permutation` / `keccak_syscall` /
/// `sha256_process_block_syscall` libfuncs, or calls into `core::pedersen` /
/// `core::poseidon` / `core::hash` / `core::keccak` / `core::sha256`) and
/// modulo operations (calls into a corelib `::rem` impl; for the raw
/// `*_safe_divmod` libfuncs of pre-inlined artifacts, only when the
/// remainder output is actually consumed — a plain division drops it, and
/// dividing a time delta is common legitimate math).
///
/// The taint is intra-function: with inlining avoided the getter call and
/// the sink typically live in the same user function body, but a block value
/// returned from a helper and hashed in the caller is missed
/// (under-reported). Confidence is Low: hashing a timestamp is also how some
/// contracts build (non-security) identifiers, and modulo on a timestamp can
/// be bucketing rather than randomness.
#[derive(Default)]
pub struct BlockValuesForRandomness {}

/// What kind of sink an invocation is, for the finding message.
enum SinkKind {
    Hash,
    Modulo,
}

impl Detector for BlockValuesForRandomness {
    fn name(&self) -> &str {
        "block-values-for-randomness"
    }

    fn description(&self) -> &str {
        "Detect block timestamp/number used as a randomness source (hashed or reduced by modulo)"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn impact(&self) -> Impact {
        Impact::Medium
    }

    fn run(&self, core: &CoreUnit) -> HashSet<Result> {
        let mut results: HashSet<Result> = HashSet::new();

        for compilation_unit in core.get_compilation_units() {
            for f in compilation_unit.functions_user_defined() {
                let sources = block_value_sources(compilation_unit, f);
                if sources.is_empty() {
                    continue;
                }
                let taint = compilation_unit.get_taint(&f.name()).unwrap();

                for stmt in f.get_statements().iter() {
                    let SierraStatement::Invocation(invoc) = stmt else {
                        continue;
                    };
                    let libfunc = compilation_unit
                        .registry()
                        .get_libfunc(&invoc.libfunc_id)
                        .expect("Library function not found in the registry");

                    let Some(kind) = sink_kind(f, invoc, libfunc) else {
                        continue;
                    };

                    // Builtins are filtered from the checked arguments: the
                    // taint over-approximation lets a data value taint the
                    // RangeCheck/GasBuiltin outputs of an operation, and
                    // those chains thread through every subsequent call.
                    let user_args = filter_builtins_from_arguments(
                        libfunc.param_signatures(),
                        invoc.args.clone(),
                    );
                    let tainted = user_args.iter().any(|arg| {
                        taint.taints_any_sources(&sources, &WrapperVariable::new(f.name(), arg.id))
                    });
                    if !tainted {
                        continue;
                    }

                    let kind_str = match kind {
                        SinkKind::Hash => "a hash function",
                        SinkKind::Modulo => "a modulo operation",
                    };
                    results.insert(Result {
                        name: self.name().to_string(),
                        impact: self.impact(),
                        confidence: self.confidence(),
                        message: format!(
                            "Sequencer controlled block value (timestamp or number) flows into {} in {}\n {}",
                            kind_str,
                            f.name(),
                            statement_summary_in_named_function(compilation_unit, &f.name(), stmt)
                        ),
                        locations: statement_locations(compilation_unit, &f.name(), stmt),
                    });
                }
            }
        }

        results
    }
}

/// Variables holding a block timestamp/number (or a value wrapping one, e.g.
/// the getter's `PanicResult`) in `function`.
fn block_value_sources(
    compilation_unit: &CompilationUnit,
    function: &Function,
) -> FxHashSet<WrapperVariable> {
    let mut sources = FxHashSet::default();

    for stmt in function.get_statements().iter() {
        let SierraStatement::Invocation(invoc) = stmt else {
            continue;
        };
        let libfunc = compilation_unit
            .registry()
            .get_libfunc(&invoc.libfunc_id)
            .expect("Library function not found in the registry");

        match libfunc {
            // Inlining avoided: the corelib getters survive as calls.
            CoreConcreteLibfunc::FunctionCall(f_called) => {
                let callee = f_called
                    .function
                    .id
                    .debug_name
                    .as_ref()
                    .map(|n| n.as_str())
                    .unwrap_or_default();
                if callee == "core::starknet::info::get_block_timestamp"
                    || callee == "core::starknet::info::get_block_number"
                {
                    if let Some(branch) = invoc.branches.first() {
                        for var in filter_builtins_from_returns(
                            &f_called.signature.branch_signatures[0].vars,
                            branch.results.clone(),
                        ) {
                            sources.insert(WrapperVariable::new(function.name(), var.id));
                        }
                    }
                }
            }
            // Pre-inlined artifacts (and get_block_info().unbox() in source):
            // the getters deconstruct the execution info's BlockInfo. Member
            // 0 is block_number, member 1 block_timestamp; member 2
            // (sequencer_address) is not a block value.
            CoreConcreteLibfunc::Struct(StructConcreteLibfunc::Deconstruct(d)) => {
                let is_block_info = d
                    .signature
                    .param_signatures
                    .first()
                    .is_some_and(|p| p.ty.to_string() == "core::starknet::info::BlockInfo");
                if is_block_info {
                    if let Some(branch) = invoc.branches.first() {
                        for var in branch.results.iter().take(2) {
                            sources.insert(WrapperVariable::new(function.name(), var.id));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    sources
}

/// Classify an invocation as a randomness-relevant sink, or `None`.
fn sink_kind(
    function: &Function,
    invoc: &GenInvocation<StatementIdx>,
    libfunc: &CoreConcreteLibfunc,
) -> Option<SinkKind> {
    use cairo_lang_sierra::extensions::starknet::StarknetConcreteLibfunc;

    match libfunc {
        // Raw hash libfuncs (pre-inlined artifacts, and `pedersen` /
        // `hades_permutation` which are extern even with inlining avoided).
        CoreConcreteLibfunc::Pedersen(_) | CoreConcreteLibfunc::Poseidon(_) => Some(SinkKind::Hash),
        CoreConcreteLibfunc::Starknet(
            StarknetConcreteLibfunc::Keccak(_) | StarknetConcreteLibfunc::Sha256ProcessBlock(_),
        ) => Some(SinkKind::Hash),
        CoreConcreteLibfunc::FunctionCall(f_called) => {
            let callee = f_called
                .function
                .id
                .debug_name
                .as_ref()
                .map(|n| n.as_str())
                .unwrap_or_default();
            if callee.starts_with("core::pedersen::")
                || callee.starts_with("core::poseidon::")
                || callee.starts_with("core::hash::")
                || callee.starts_with("core::keccak::")
                || callee.starts_with("core::sha256::")
            {
                Some(SinkKind::Hash)
            } else if callee.starts_with("core::") && callee.ends_with("::rem") {
                Some(SinkKind::Modulo)
            } else {
                None
            }
        }
        // Raw `*_safe_divmod` (pre-inlined artifacts): `%` and `/` both
        // lower to it. Only a consumed remainder output indicates a modulo.
        _ => {
            let name = invoc
                .libfunc_id
                .debug_name
                .as_ref()
                .map(|n| n.as_str())
                .unwrap_or_default();
            if name.contains("safe_divmod") && divmod_remainder_used(function, invoc, libfunc) {
                Some(SinkKind::Modulo)
            } else {
                None
            }
        }
    }
}

/// True when the remainder output of a raw `*_safe_divmod` is consumed by
/// something other than an immediate `drop` — i.e. the source expression was
/// a `%` (or used both outputs), not a plain `/`.
fn divmod_remainder_used(
    function: &Function,
    invoc: &GenInvocation<StatementIdx>,
    libfunc: &CoreConcreteLibfunc,
) -> bool {
    let Some(branch) = invoc.branches.first() else {
        return false;
    };
    let outputs =
        filter_builtins_from_returns(&libfunc.branch_signatures()[0].vars, branch.results.clone());
    // Non-builtin outputs are (quotient, remainder, ...guarantees).
    let Some(remainder) = outputs.get(1) else {
        return false;
    };
    let consumer = function
        .get_statements()
        .iter()
        .find_map(|stmt| match stmt {
            SierraStatement::Invocation(consumer)
                if consumer.args.iter().any(|a| a.id == remainder.id)
                    && !std::ptr::eq(consumer, invoc) =>
            {
                Some(consumer)
            }
            _ => None,
        });
    match consumer {
        Some(consumer) => !consumer
            .libfunc_id
            .debug_name
            .as_ref()
            .is_some_and(|n| n.starts_with("drop<")),
        None => false,
    }
}

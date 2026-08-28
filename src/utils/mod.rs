use crate::core::basic_block::BasicBlock;
use crate::core::compilation_unit::CompilationUnit;
use crate::core::core_unit::CoreUnit;
use crate::core::source_map::SourceLocation;
use cairo_lang_sierra::extensions::lib_func::{OutputVarInfo, ParamSignature};
use cairo_lang_sierra::ids::VarId;
use cairo_lang_sierra::program::{GenStatement, Statement as SierraStatement};
use num_bigint::BigInt;
use num_traits::Num;

pub const BUILTINS: [&str; 8] = [
    "Pedersen",
    "RangeCheck",
    "Bitwise",
    "EcOp",
    "Poseidon",
    "SegmentArena",
    "GasBuiltin",
    "System",
];

/// Filter the builtins from a function signature
pub fn filter_builtins_from_signature(signature: &[ParamSignature]) -> Vec<&ParamSignature> {
    signature
        .iter()
        .filter(|sig_elem| !BUILTINS.contains(&sig_elem.ty.debug_name.as_ref().unwrap().as_str()))
        .collect()
}

/// Filter the builtins arguments and returns only the user defined arguments
pub fn filter_builtins_from_arguments(
    signature: &[ParamSignature],
    arguments: Vec<VarId>,
) -> Vec<VarId> {
    signature
        .iter()
        .zip(arguments)
        .filter(|(sig_elem, _)| {
            !BUILTINS.contains(&sig_elem.ty.debug_name.as_ref().unwrap().as_str())
        })
        .map(|(_, arg_elem)| arg_elem)
        .collect()
}

/// Filter the builtins from the return variables and returns only the user defined variables
pub fn filter_builtins_from_returns(
    signature: &[OutputVarInfo],
    returns: Vec<VarId>,
) -> Vec<VarId> {
    signature
        .iter()
        .zip(returns)
        .filter(|(sig_elem, _)| {
            !BUILTINS.contains(&sig_elem.ty.debug_name.as_ref().unwrap().as_str())
        })
        .map(|(_, arg_elem)| arg_elem)
        .collect()
}

/// Skip leading statements that are pure bookkeeping — they don't consume or
/// produce the data values the dropped-return detectors track — so they can't
/// affect whether a return value is used. The compiler freely interleaves
/// these with the drop/deconstruct sequence those detectors pattern-match
/// (e.g. a `disable_ap_tracking` between the `branch_align` and the `drop`,
/// or a `redeposit_gas` right after a `branch_align` on cairo >= 2.6).
pub fn skip_bookkeeping(mut stmts: &[SierraStatement]) -> &[SierraStatement] {
    while let Some(SierraStatement::Invocation(invoc)) = stmts.first() {
        let is_bookkeeping = invoc.libfunc_id.debug_name.as_ref().is_some_and(|n| {
            n == "branch_align"
                || n == "disable_ap_tracking"
                || n == "enable_ap_tracking"
                || n == "redeposit_gas"
        });
        if !is_bookkeeping {
            break;
        }
        stmts = &stmts[1..];
    }
    stmts
}

/// Trace a sierra variable within a function's statements back to the
/// `const_as_immediate<Const<felt252, N>>` that produced it, if any. Follows
/// forwarding libfuncs (`store_temp`, `rename`, `dup`) that just move the
/// value along. Returns `None` if the variable is not a compile-time constant
/// (e.g. it was read from calldata, the result of a deconstruct, etc).
pub fn trace_const_felt252(statements: &[SierraStatement], mut var_id: u64) -> Option<BigInt> {
    // Guard against pathological loops — in practice the dependency chain
    // between const_as_immediate and its first consumer is short, but if we
    // ever hit a cycle (e.g. from a join point in a CFG), bail out.
    for _ in 0..256 {
        let producer = statements.iter().find_map(|stmt| match stmt {
            SierraStatement::Invocation(invoc)
                if invoc
                    .branches
                    .iter()
                    .any(|b| b.results.iter().any(|r| r.id == var_id)) =>
            {
                Some(invoc)
            }
            _ => None,
        })?;
        let name = producer.libfunc_id.debug_name.as_ref()?.as_str();
        if let Some(rest) = name.strip_prefix("const_as_immediate<Const<felt252, ") {
            let value = rest.strip_suffix(">>")?;
            return if let Some(hex) = value.strip_prefix("0x") {
                BigInt::from_str_radix(hex, 16).ok()
            } else {
                BigInt::from_str_radix(value, 10).ok()
            };
        }
        if name.starts_with("store_temp<")
            || name.starts_with("rename<")
            || name.starts_with("dup<")
        {
            var_id = producer.args.first()?.id;
            continue;
        }
        return None;
    }
    None
}

/// Trace a sierra variable holding a storage address back to the
/// `storage_base_address_const<N>` that produced it, if any. `N` is the
/// hashed name of the storage variable, so it identifies which variable a
/// `storage_read_syscall`/`storage_write_syscall` touches even though the
/// inlined sierra carries no variable name. Follows the plumbing libfuncs
/// the compiler emits between the const and the syscall
/// (`storage_address_from_base`, the `StoragePointer` struct dance,
/// `snapshot_take`, and the usual forwarding moves).
pub fn trace_storage_base_address(
    statements: &[SierraStatement],
    mut var_id: u64,
) -> Option<BigInt> {
    for _ in 0..256 {
        let producer = statements.iter().find_map(|stmt| match stmt {
            SierraStatement::Invocation(invoc)
                if invoc
                    .branches
                    .iter()
                    .any(|b| b.results.iter().any(|r| r.id == var_id)) =>
            {
                Some(invoc)
            }
            _ => None,
        })?;
        let name = producer.libfunc_id.debug_name.as_ref()?.as_str();
        if let Some(rest) = name.strip_prefix("storage_base_address_const<") {
            let value = rest.strip_suffix('>')?;
            return if let Some(hex) = value.strip_prefix("0x") {
                BigInt::from_str_radix(hex, 16).ok()
            } else {
                BigInt::from_str_radix(value, 10).ok()
            };
        }
        let forwards = name == "storage_address_from_base"
            || name.starts_with("storage_address_from_base_and_offset")
            || name.starts_with("snapshot_take<")
            || name.starts_with("struct_deconstruct<")
            || name.starts_with("store_temp<")
            || name.starts_with("rename<")
            || name.starts_with("dup<")
            // A multi-member construct would make "first argument" ambiguous
            || (name.starts_with("struct_construct<") && producer.args.len() == 1);
        if forwards {
            var_id = producer.args.first()?.id;
            continue;
        }
        return None;
    }
    None
}

/// Trace a sierra variable holding a storage-base struct back to the
/// `struct_deconstruct<...::StorageStorageBase(Mut)?>` that produced it, if
/// any. With inlining avoided (cairo >= 2.6) each storage variable is one
/// member of the contract's storage-base struct, so the (struct, member
/// index) pair identifies the variable. The `Mut` suffix is stripped so a
/// read through `StorageStorageBase` pairs with a write through
/// `StorageStorageBaseMut`.
pub fn trace_storage_base_member(
    statements: &[SierraStatement],
    mut var_id: u64,
) -> Option<String> {
    for _ in 0..256 {
        let producer = statements.iter().find_map(|stmt| match stmt {
            SierraStatement::Invocation(invoc)
                if invoc
                    .branches
                    .iter()
                    .any(|b| b.results.iter().any(|r| r.id == var_id)) =>
            {
                Some(invoc)
            }
            _ => None,
        })?;
        let name = producer.libfunc_id.debug_name.as_ref()?.as_str();
        if let Some(rest) = name.strip_prefix("struct_deconstruct<") {
            let ty = rest.strip_suffix('>')?;
            if !ty.contains("StorageStorageBase") {
                return None;
            }
            let member_index = producer
                .branches
                .first()?
                .results
                .iter()
                .position(|r| r.id == var_id)?;
            return Some(format!("{}#{}", ty.trim_end_matches("Mut"), member_index));
        }
        let forwards = name.starts_with("snapshot_take<")
            || name.starts_with("store_temp<")
            || name.starts_with("rename<")
            || name.starts_with("dup<");
        if forwards {
            var_id = producer.args.first()?.id;
            continue;
        }
        return None;
    }
    None
}

/// Identity of the storage variable a read/write statement touches, used to
/// pair reads and writes of the same variable across functions. For the
/// corelib accessor form (inlining avoided, cairo >= 2.6) the callee name is
/// generic over the stored type, so the identity is the traced storage-base
/// struct member; for the pre-2.6 `FunctionCall` form the identity is the
/// function path minus its trailing `::read`/`::write`; for the raw syscall
/// form (inlined cairo 2.11+ sierra) it is the traced
/// `storage_base_address_const` value (the 4th syscall argument is the
/// storage address for both read and write). Returns `None` when the
/// identity cannot be determined.
pub fn storage_statement_identity(
    stmt: &SierraStatement,
    function_statements: &[SierraStatement],
) -> Option<String> {
    if let SierraStatement::Invocation(invoc) = stmt {
        let name = invoc.libfunc_id.debug_name.as_ref()?.as_str();
        if name.starts_with("storage_read_syscall") || name.starts_with("storage_write_syscall") {
            let address_var = invoc.args.get(3)?;
            return trace_storage_base_address(function_statements, address_var.id)
                .map(|n| n.to_string());
        }
        if name.starts_with("function_call<user@core::starknet::storage") {
            // The storage-base struct is one of the call arguments (after the
            // implicit builtins); trace each until one resolves.
            return invoc
                .args
                .iter()
                .find_map(|arg| trace_storage_base_member(function_statements, arg.id));
        }
    }
    format!("{stmt}")
        .rsplit_once("::")
        .map(|(p, _)| p.to_string())
}

/// Identity of the storage variable a read/write statement touches, computed
/// against the statements of the function that owns the statement — reads
/// and writes can be recorded in a different function than the one under
/// analysis (through the reentrancy analysis' private-call recursion), and
/// the `struct_deconstruct` the identity is traced from lives in the owner.
/// Returns an empty string when the identity cannot be determined; callers
/// treat that as a wildcard that matches any variable rather than dropping
/// the finding.
pub fn storage_variable_identity(
    compilation_unit: &CompilationUnit,
    owner: &str,
    stmt: &SierraStatement,
) -> String {
    compilation_unit
        .function_by_name(owner)
        .and_then(|f| storage_statement_identity(stmt, f.get_statements()))
        .unwrap_or_default()
}

/// Return true if the external call inside this basic block targets one of
/// the allowlisted safe external calls. Two shapes are handled:
/// - dispatcher `FunctionCall` statements (inlining avoided, or pre-2.11
///   sierra): matched by name against the configured safe external calls
///   (e.g. `::safe_foo` matches `...IAnotherContractDispatcherImpl::safe_foo`)
/// - raw `call_contract_syscall` / `library_call_syscall` (inlined cairo
///   2.11+ sierra): their 4th argument is the `felt252` selector of the
///   called entrypoint, matched against the selectors' `starknet_keccak`.
pub fn is_safe_external_call(
    call: &BasicBlock,
    function_statements: &[SierraStatement],
    core: &CoreUnit,
) -> bool {
    let Some(instr) = call.get_function_call() else {
        return false;
    };
    let GenStatement::Invocation(invoc) = instr.get_statement() else {
        return false;
    };
    let libfunc_name = invoc
        .libfunc_id
        .debug_name
        .as_ref()
        .map(|n| n.as_str())
        .unwrap_or_default();
    if let Some(callee) = libfunc_name
        .strip_prefix("function_call<user@")
        .and_then(|n| n.strip_suffix('>'))
    {
        if let Some(safe_calls) = core.get_safe_external_calls() {
            return safe_calls.iter().any(|safe| callee.contains(safe.as_str()));
        }
        return false;
    }
    let Some(safe_selectors) = core.get_safe_external_selectors() else {
        return false;
    };
    let Some(selector_var) = invoc.args.get(3) else {
        return false;
    };
    let Some(selector_val) = trace_const_felt252(function_statements, selector_var.id) else {
        return false;
    };
    safe_selectors.iter().any(|s| s == &selector_val)
}

/// Strip generic arguments from a (possibly turbofish) path:
/// `Impl::<A, B<C>>::write` -> `Impl::write`, `emit::<E, F>` -> `emit`.
fn strip_generic_args(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut depth = 0usize;
    for c in path.chars() {
        match c {
            '<' => {
                if depth == 0 && out.ends_with("::") {
                    out.truncate(out.len() - 2);
                }
                depth += 1;
            }
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Render a sierra statement for a finding message. VarIds and branch
/// targets are compiler-assigned and churn on every compiler bump, so they
/// never appear: `function_call<user@PATH>(args) -> (results)` renders as
/// the callee PATH with its generic arguments stripped (the fully-generic
/// corelib accessor paths run to ~1.5KB otherwise), and any other libfunc
/// renders as the libfunc name alone — short generic arguments like
/// `<felt252>` are kept, argument/result lists and branch info never are.
pub fn statement_summary(stmt: &SierraStatement) -> String {
    let SierraStatement::Invocation(invoc) = stmt else {
        // Return statements are never the subject of a finding message.
        return "return".to_string();
    };
    let name = invoc.libfunc_id.to_string();
    if let Some(callee) = name
        .strip_prefix("function_call<user@")
        .and_then(|n| n.strip_suffix('>'))
    {
        return strip_generic_args(callee);
    }
    if name.len() > 80 {
        if let Some((base, _)) = name.split_once('<') {
            return base.to_string();
        }
    }
    name
}

/// Like `statement_summary`, with a stable occurrence ordinal appended when
/// the summary alone is ambiguous within the owning function's statements —
/// e.g. two calls to the same callee in different branches render as
/// `…::foo (1st occurrence)` / `…::foo (2nd occurrence)`. Results are
/// collected in a HashSet keyed partly by message, so without the ordinal
/// such findings would collapse into one; occurrence order is stable across
/// compiler bumps, unlike VarIds.
pub fn statement_summary_in_function(
    stmt: &SierraStatement,
    owner_statements: &[SierraStatement],
) -> String {
    let summary = statement_summary(stmt);
    let occurrences: Vec<&SierraStatement> = owner_statements
        .iter()
        .filter(|s| statement_summary(s) == summary)
        .collect();
    if occurrences.len() > 1 {
        if let Some(position) = occurrences.iter().position(|s| *s == stmt) {
            return format!(
                "{} ({} occurrence)",
                summary,
                number_to_ordinal(position as u64 + 1)
            );
        }
    }
    summary
}

/// Summary of a statement disambiguated within the function that owns it,
/// resolved by name — reads/writes/calls can be recorded in a different
/// function than the one under analysis (through the reentrancy analysis'
/// private-call recursion). Falls back to the bare summary when the owner
/// cannot be resolved. When the statement maps to Cairo source of the
/// analyzed target, the location is appended as ` (path/to/file.cairo:LINE)`;
/// statements without a mapping (pre-built artifacts, corelib-owned code)
/// keep the location-less summary.
pub fn statement_summary_in_named_function(
    compilation_unit: &CompilationUnit,
    owner: &str,
    stmt: &SierraStatement,
) -> String {
    let summary = match compilation_unit.function_by_name(owner) {
        Some(f) => statement_summary_in_function(stmt, f.get_statements()),
        None => statement_summary(stmt),
    };
    match compilation_unit.statement_location(owner, stmt) {
        Some(location) => format!("{summary} ({location})"),
        None => summary,
    }
}

/// A function name for a finding message, with its Cairo declaration site
/// appended as ` (path/to/file.cairo:LINE)` when available. Functions
/// without a mapping (pre-built artifacts, unresolvable names) render as the
/// bare name.
pub fn function_summary(compilation_unit: &CompilationUnit, name: &str) -> String {
    match compilation_unit.function_location(name) {
        Some(location) => format!("{name} ({location})"),
        None => name.to_string(),
    }
}

/// Structured location of a statement for `detector::Result::locations`:
/// zero-or-one element, mirroring the location
/// `statement_summary_in_named_function` bakes into the message.
pub fn statement_locations(
    compilation_unit: &CompilationUnit,
    owner: &str,
    stmt: &SierraStatement,
) -> Vec<SourceLocation> {
    compilation_unit
        .statement_location(owner, stmt)
        .cloned()
        .into_iter()
        .collect()
}

/// Structured declaration site of a function for
/// `detector::Result::locations`: zero-or-one element, mirroring the
/// location `function_summary` bakes into the message.
pub fn function_locations(compilation_unit: &CompilationUnit, name: &str) -> Vec<SourceLocation> {
    compilation_unit
        .function_location(name)
        .cloned()
        .into_iter()
        .collect()
}

/// Compact human form of a `storage_statement_identity` /
/// `storage_variable_identity` result for finding messages:
/// `path::to::Contract::StorageStorageBase#2` renders as
/// "Storage variable #2 of path::to::Contract". Identities in other forms
/// (pre-2.6 accessor paths, raw hashed storage addresses) return `None`.
pub fn storage_identity_pretty(identity: &str) -> Option<String> {
    let (ty, index) = identity.rsplit_once('#')?;
    let contract = ty.strip_suffix("::StorageStorageBase")?;
    if contract.is_empty() || index.is_empty() || !index.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("Storage variable #{index} of {contract}"))
}

/// Get a number as input and return the ordinal representation
pub fn number_to_ordinal(n: u64) -> String {
    let s = n.to_string();
    if s.ends_with('1') && !s.ends_with("11") {
        format!("{}{}", n, "st")
    } else if s.ends_with('2') && !s.ends_with("12") {
        format!("{}{}", n, "nd")
    } else if s.ends_with('3') && !s.ends_with("13") {
        format!("{}{}", n, "rd")
    } else {
        format!("{}{}", n, "th")
    }
}

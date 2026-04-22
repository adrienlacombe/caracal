use crate::core::basic_block::BasicBlock;
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
#[allow(dead_code)]
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

/// Return true if the external call inside this basic block targets one of
/// the allowlisted safe selectors. Matches `call_contract_syscall` and
/// `library_call_syscall`: their 4th argument is the `felt252` selector of
/// the called entrypoint.
pub fn is_safe_syscall(
    call: &BasicBlock,
    function_statements: &[SierraStatement],
    safe_selectors: &[BigInt],
) -> bool {
    let Some(instr) = call.get_function_call() else {
        return false;
    };
    let GenStatement::Invocation(invoc) = instr.get_statement() else {
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

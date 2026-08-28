//! Unit tests for the analysis helpers in `caracal::utils` — the statement
//! tracers and message builders every detector depends on.
//!
//! Strategy: instead of hand-building whole SIERRA programs, a small
//! purpose-built fixture is compiled through the lib API (same pattern as
//! `tests/integration_tests.rs`) and the helpers are fed real statements
//! located inside it; assertions are on the RESULTS (the traced const equals
//! the literal written in the fixture, identities of a read and a write of
//! the same variable pair up, ...). Only the shapes the modern
//! inlining-avoided compilation can no longer produce (the pre-2.6 /
//! fully-inlined raw-syscall storage form) are covered with hand-built
//! statements.

use cairo_lang_sierra::ids::{ConcreteLibfuncId, VarId};
use cairo_lang_sierra::program::{
    GenBranchInfo, GenBranchTarget, GenInvocation, GenStatement, Statement as SierraStatement,
};
use caracal::core::cfg::Cfg;
use caracal::core::compilation_unit::CompilationUnit;
use caracal::core::core_unit::{CoreOpts, CoreUnit};
use caracal::core::function::Function;
use caracal::utils::{
    is_safe_external_call, number_to_ordinal, skip_bookkeeping, statement_summary,
    statement_summary_in_function, statement_summary_in_named_function, storage_identity_pretty,
    storage_statement_identity, trace_const_felt252, trace_storage_base_address,
    trace_storage_base_member,
};
use num_bigint::BigInt;
use std::env;

/// The purpose-built fixture. Every test below locates statements in it by
/// shape, never by index, so it stays robust against codegen shifts.
const FIXTURE: &str = r#"
#[starknet::interface]
trait IOther<T> {
    fn foo(self: @T, a: felt252);
    fn safe_foo(self: @T, a: felt252);
}

#[starknet::contract]
mod UtilsFixture {
    use super::IOtherDispatcherTrait;
    use super::IOtherDispatcher;
    use starknet::ContractAddress;

    #[storage]
    struct Storage {
        first: felt252,
        second: felt252,
    }

    #[external(v0)]
    fn write_const(ref self: ContractState) {
        self.first.write(42);
    }

    #[external(v0)]
    fn touch_both(ref self: ContractState) -> felt252 {
        let a = self.first.read();
        let b = self.second.read();
        self.second.write(7);
        a + b
    }

    #[external(v0)]
    fn call_twice(ref self: ContractState, address: ContractAddress) {
        IOtherDispatcher { contract_address: address }.foo(1);
        IOtherDispatcher { contract_address: address }.foo(2);
    }

    #[external(v0)]
    fn call_safe(ref self: ContractState, address: ContractAddress) {
        IOtherDispatcher { contract_address: address }.safe_foo(3);
    }
}
"#;

/// Write the fixture into a per-test scratch directory and compile it with
/// the bundled compiler, exactly like the snapshot harness does. Per-test
/// directories keep parallel tests from racing on the same file.
fn compile_fixture(label: &str) -> CoreUnit {
    let dir = env::temp_dir().join(format!(
        "caracal-utils-helpers-{label}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("utils_fixture.cairo");
    std::fs::write(&target, FIXTURE).unwrap();
    let opts = CoreOpts {
        target,
        corelib: Some(format!("{}/corelib/src", env::var("CARGO_MANIFEST_DIR").unwrap()).into()),
        contract_path: None,
        safe_external_calls: Some(vec!["::safe_foo".to_string()]),
    };
    CoreUnit::new(opts).unwrap()
}

/// The single compilation unit of the fixture.
fn compilation_unit(core: &CoreUnit) -> &CompilationUnit {
    let units = core.get_compilation_units();
    assert_eq!(units.len(), 1);
    &units[0]
}

/// The (inner, user-body) function whose name ends with `suffix`.
fn function_ending_with<'a>(unit: &'a CompilationUnit, suffix: &str) -> &'a Function {
    unit.functions()
        .find(|f| f.name().ends_with(suffix))
        .unwrap_or_else(|| {
            panic!(
                "no function ending with {suffix}; have: {:?}",
                unit.functions().map(|f| f.name()).collect::<Vec<_>>()
            )
        })
}

/// Statements of `function` whose summary starts/ends with the given parts.
fn statements_matching<'a>(
    function: &'a Function,
    prefix: &str,
    suffix: &str,
) -> Vec<&'a SierraStatement> {
    function
        .get_statements()
        .iter()
        .filter(|s| {
            let summary = statement_summary(s);
            summary.starts_with(prefix) && summary.ends_with(suffix)
        })
        .collect()
}

fn invocation_of(
    stmt: &SierraStatement,
) -> &GenInvocation<cairo_lang_sierra::program::StatementIdx> {
    match stmt {
        GenStatement::Invocation(invoc) => invoc,
        GenStatement::Return(_) => panic!("expected an invocation"),
    }
}

// ---------------------------------------------------------------------------
// Compiled-fixture tests
// ---------------------------------------------------------------------------

#[test]
fn trace_const_felt252_recovers_written_literal() {
    let core = compile_fixture("const");
    let unit = compilation_unit(&core);
    let f = function_ending_with(unit, "::UtilsFixture::write_const");

    // The corelib storage-accessor call that performs `self.first.write(42)`:
    // its last argument is the value written, which must trace back to the
    // literal 42 through the forwarding moves the compiler inserts.
    let writes = statements_matching(f, "core::starknet::storage", "::write");
    assert_eq!(writes.len(), 1, "one storage write in write_const");
    let invoc = invocation_of(writes[0]);
    let value_var = invoc.args.last().unwrap();
    assert_eq!(
        trace_const_felt252(f.get_statements(), value_var.id),
        Some(BigInt::from(42))
    );

    // The storage-base argument of the same call is NOT a compile-time
    // felt252 const.
    let base_var = &invoc.args[invoc.args.len() - 2];
    assert_eq!(trace_const_felt252(f.get_statements(), base_var.id), None);
}

#[test]
fn storage_identities_pair_reads_and_writes_per_variable() {
    let core = compile_fixture("identity");
    let unit = compilation_unit(&core);
    let f = function_ending_with(unit, "::UtilsFixture::touch_both");
    let stmts = f.get_statements();

    // touch_both reads `first` then `second`, then writes `second`.
    let reads = statements_matching(f, "core::starknet::storage", "::read");
    assert_eq!(reads.len(), 2, "two storage reads in touch_both");
    let writes = statements_matching(f, "core::starknet::storage", "::write");
    assert_eq!(writes.len(), 1, "one storage write in touch_both");

    let read_first = storage_statement_identity(reads[0], stmts).unwrap();
    let read_second = storage_statement_identity(reads[1], stmts).unwrap();
    let write_second = storage_statement_identity(writes[0], stmts).unwrap();

    // Same variable => same identity; different variable => different.
    assert_eq!(read_second, write_second);
    assert_ne!(read_first, read_second);

    // The identity is the (storage-base struct, member index) pair, with the
    // Mut suffix stripped so reads pair with writes. `first` is member #0,
    // `second` member #1.
    assert!(
        read_first.ends_with("::UtilsFixture::StorageStorageBase#0"),
        "unexpected identity: {read_first}"
    );
    assert!(
        write_second.ends_with("::UtilsFixture::StorageStorageBase#1"),
        "unexpected identity: {write_second}"
    );

    // trace_storage_base_member is the tracer behind those identities: the
    // write call's storage-base argument resolves to member #1.
    let member = invocation_of(writes[0])
        .args
        .iter()
        .find_map(|arg| trace_storage_base_member(stmts, arg.id))
        .expect("write call's base argument traces to a storage-base member");
    assert_eq!(member, write_second);

    // And the human-readable form detectors print:
    assert_eq!(
        storage_identity_pretty(&read_first).unwrap(),
        format!(
            "Storage variable #0 of {}",
            read_first.strip_suffix("::StorageStorageBase#0").unwrap()
        )
    );
}

#[test]
fn statement_summaries_are_stable_and_disambiguated() {
    let core = compile_fixture("summary");
    let unit = compilation_unit(&core);

    // Generic stripping: the fully-generic corelib accessor path (~1.5KB of
    // turbofish) renders as the bare callee path.
    let f = function_ending_with(unit, "::UtilsFixture::write_const");
    let writes = statements_matching(f, "core::starknet::storage", "::write");
    assert_eq!(
        statement_summary(writes[0]),
        "core::starknet::storage::StorablePointerWriteAccessImpl::write"
    );

    // No summary ever leaks VarIds, arg/result lists or branch targets.
    for stmt in f.get_statements() {
        let summary = statement_summary(stmt);
        for forbidden in ["([", " -> ", "fallthrough"] {
            assert!(
                !summary.contains(forbidden),
                "summary leaks compiler-assigned ids: {summary}"
            );
        }
    }

    // Return statements render as a plain keyword.
    let ret = f
        .get_statements()
        .iter()
        .find(|s| matches!(s, GenStatement::Return(_)))
        .unwrap();
    assert_eq!(statement_summary(ret), "return");

    // Occurrence ordinals: two calls to the same callee in one function are
    // ambiguous by summary alone and get stable ordinals appended...
    let f = function_ending_with(unit, "::UtilsFixture::call_twice");
    let calls = statements_matching(f, "", "IOtherDispatcherImpl::foo");
    assert_eq!(calls.len(), 2, "two dispatcher calls in call_twice");
    assert_eq!(
        statement_summary_in_function(calls[0], f.get_statements()),
        format!("{} (1st occurrence)", statement_summary(calls[0]))
    );
    assert_eq!(
        statement_summary_in_function(calls[1], f.get_statements()),
        format!("{} (2nd occurrence)", statement_summary(calls[1]))
    );

    // ...while a unique statement keeps the bare summary.
    let f = function_ending_with(unit, "::UtilsFixture::call_safe");
    let calls = statements_matching(f, "", "IOtherDispatcherImpl::safe_foo");
    assert_eq!(calls.len(), 1);
    assert_eq!(
        statement_summary_in_function(calls[0], f.get_statements()),
        statement_summary(calls[0])
    );

    // The named-function variant resolves the owner and appends the Cairo
    // source location (path relative to the analyzed target).
    let summary = statement_summary_in_named_function(unit, &f.name(), calls[0]);
    assert!(
        summary.starts_with(&statement_summary(calls[0])),
        "unexpected summary: {summary}"
    );
    assert!(
        summary.contains("(utils_fixture.cairo:"),
        "missing source location: {summary}"
    );
}

#[test]
fn is_safe_external_call_honors_allowlist_in_both_shapes() {
    let core = compile_fixture("safe-call");
    let unit = compilation_unit(&core);

    // Shape 1: dispatcher FunctionCall statements (inlining avoided), matched
    // by callee name against the configured `::safe_foo`.
    let external_call_block = |name: &str| {
        let f = function_ending_with(unit, name);
        let bb = f
            .get_cfg()
            .get_basic_blocks()
            .iter()
            .find(|bb| bb.get_external_call().is_some())
            .unwrap_or_else(|| panic!("no external call block in {name}"));
        (bb, f.get_statements())
    };

    let (safe_bb, safe_stmts) = external_call_block("::UtilsFixture::call_safe");
    assert!(is_safe_external_call(safe_bb, safe_stmts, &core));

    let (unsafe_bb, unsafe_stmts) = external_call_block("::UtilsFixture::call_twice");
    assert!(!is_safe_external_call(unsafe_bb, unsafe_stmts, &core));

    // Shape 2: the raw `call_contract_syscall` (what fully-inlined cairo
    // 2.11+ sierra exposes) lives inside the dispatcher impls themselves;
    // its 4th argument is the const entrypoint selector, matched against
    // starknet_keccak of the allowlisted name.
    let (safe_bb, safe_stmts) = external_call_block("IOtherDispatcherImpl::safe_foo");
    assert!(is_safe_external_call(safe_bb, safe_stmts, &core));

    let (unsafe_bb, unsafe_stmts) = external_call_block("IOtherDispatcherImpl::foo");
    assert!(!is_safe_external_call(unsafe_bb, unsafe_stmts, &core));

    // The selector itself is a compile-time felt252 const the tracer must
    // resolve (that is how the syscall shape above gets matched).
    let invoc = invocation_of(
        safe_bb
            .get_external_call()
            .as_ref()
            .unwrap()
            .get_statement(),
    );
    let selector = trace_const_felt252(safe_stmts, invoc.args[3].id);
    assert!(selector.is_some(), "selector must trace to a const");
}

// ---------------------------------------------------------------------------
// Hand-built statements: shapes modern compilation no longer produces
// ---------------------------------------------------------------------------

/// A single-branch (fallthrough) invocation statement. The tracers only look
/// at libfunc debug names, args and branch results, so this is a faithful
/// stand-in for pre-built-artifact sierra.
fn invocation(libfunc: &str, args: &[u64], results: &[u64]) -> SierraStatement {
    GenStatement::Invocation(GenInvocation {
        libfunc_id: ConcreteLibfuncId::from_string(libfunc),
        args: args.iter().copied().map(VarId::new).collect(),
        branches: vec![GenBranchInfo {
            target: GenBranchTarget::Fallthrough,
            results: results.iter().copied().map(VarId::new).collect(),
        }],
    })
}

#[test]
fn trace_storage_base_address_resolves_syscall_shape() {
    // The fully-inlined (cairo 2.11+ artifact) storage form: a hashed-name
    // address const, plumbed through the usual forwarding libfuncs into the
    // 4th syscall argument.
    let stmts = vec![
        invocation("storage_base_address_const<1234567>", &[], &[1]),
        invocation("store_temp<StorageBaseAddress>", &[1], &[2]),
        invocation("storage_address_from_base", &[2], &[3]),
        invocation("store_temp<StorageAddress>", &[3], &[4]),
        invocation("storage_read_syscall", &[10, 11, 12, 4], &[5, 6]),
        invocation("storage_write_syscall", &[10, 11, 12, 4, 8], &[7]),
    ];

    assert_eq!(
        trace_storage_base_address(&stmts, 4),
        Some(BigInt::from(1234567))
    );
    // Hex-rendered consts parse too.
    let hex = vec![invocation("storage_base_address_const<0x2a>", &[], &[1])];
    assert_eq!(trace_storage_base_address(&hex, 1), Some(BigInt::from(42)));
    // A variable nothing in the function produces (e.g. a parameter) has no
    // traceable const.
    assert_eq!(trace_storage_base_address(&stmts, 99), None);

    // storage_statement_identity uses that trace for the syscall shape, so a
    // read and a write of the same address pair up.
    let read_id = storage_statement_identity(&stmts[4], &stmts).unwrap();
    let write_id = storage_statement_identity(&stmts[5], &stmts).unwrap();
    assert_eq!(read_id, "1234567");
    assert_eq!(read_id, write_id);
}

#[test]
fn storage_statement_identity_falls_back_for_pre26_accessors() {
    // Pre-2.6 sierra: per-variable accessor functions; the identity is the
    // rendered path minus the trailing ::read / ::write, so the two pair up.
    let read = invocation(
        "function_call<user@ctr::ctr::C::balance::InternalContractMemberStateImpl::read>",
        &[0],
        &[1],
    );
    let write = invocation(
        "function_call<user@ctr::ctr::C::balance::InternalContractMemberStateImpl::write>",
        &[0, 2],
        &[3],
    );
    let other = invocation(
        "function_call<user@ctr::ctr::C::owner::InternalContractMemberStateImpl::read>",
        &[0],
        &[4],
    );
    let stmts = [read, write, other];
    let read_id = storage_statement_identity(&stmts[0], &stmts).unwrap();
    let write_id = storage_statement_identity(&stmts[1], &stmts).unwrap();
    let other_id = storage_statement_identity(&stmts[2], &stmts).unwrap();
    assert_eq!(read_id, write_id);
    assert_ne!(read_id, other_id);
}

#[test]
fn skip_bookkeeping_skips_exactly_the_bookkeeping_prefix() {
    let stmts = vec![
        invocation("branch_align", &[], &[]),
        invocation("disable_ap_tracking", &[], &[]),
        invocation("enable_ap_tracking", &[], &[]),
        invocation("redeposit_gas", &[0], &[1]),
        invocation("drop<felt252>", &[1], &[]),
        invocation("branch_align", &[], &[]),
    ];
    // Skips all four bookkeeping libfuncs, stops at the first real
    // statement, and does NOT skip bookkeeping past it.
    assert_eq!(skip_bookkeeping(&stmts), &stmts[4..]);
    // A slice already starting with a real statement is untouched.
    assert_eq!(skip_bookkeeping(&stmts[4..]), &stmts[4..]);
    // All-bookkeeping (and empty) slices drain to empty without panicking.
    assert!(skip_bookkeeping(&stmts[..3]).is_empty());
    assert!(skip_bookkeeping(&[]).is_empty());
}

#[test]
fn number_to_ordinal_english_rules() {
    for (n, expected) in [
        (1, "1st"),
        (2, "2nd"),
        (3, "3rd"),
        (4, "4th"),
        (11, "11th"),
        (12, "12th"),
        (13, "13th"),
        (21, "21st"),
        (22, "22nd"),
        (23, "23rd"),
        (101, "101st"),
        (111, "111th"),
    ] {
        assert_eq!(number_to_ordinal(n), expected);
    }
}

#[test]
fn storage_identity_pretty_only_renders_member_identities() {
    assert_eq!(
        storage_identity_pretty("a::b::C::StorageStorageBase#2"),
        Some("Storage variable #2 of a::b::C".to_string())
    );
    // Raw hashed addresses, pre-2.6 paths and malformed member indexes stay
    // as-is (caller prints the raw identity instead).
    assert_eq!(storage_identity_pretty("1234567"), None);
    assert_eq!(storage_identity_pretty("a::b::C::StorageStorageBase"), None);
    assert_eq!(
        storage_identity_pretty("a::b::C::StorageStorageBase#x1"),
        None
    );
    assert_eq!(storage_identity_pretty("::StorageStorageBase#1"), None);
}

//! Smoke tests for the `print` subcommand and both printers (cfg,
//! callgraph). The printers write their `.dot` files into the process
//! working directory, so every run happens through the real binary
//! (`CARGO_BIN_EXE_caracal`) with a scratch directory as cwd — nothing may
//! touch the repository checkout.

use graphviz_rust::dot_structures::{Graph, Stmt};
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURE: &str = "tests/detectors/reentrancy.cairo";

fn scratch_dir(label: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("caracal-printer-{label}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `caracal print` on the reentrancy fixture with `cwd` as working
/// directory (where the printer drops its .dot files).
fn run_printer(cwd: &Path, printer: &str) -> Output {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_caracal"))
        .args([
            "print",
            &format!("{manifest_dir}/{FIXTURE}"),
            "--corelib",
            &format!("{manifest_dir}/corelib/src"),
            "--printer",
            printer,
        ])
        .current_dir(cwd)
        .output()
        .expect("caracal binary runs");
    assert!(
        output.status.success(),
        "caracal print --printer {printer} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// All .dot files written into `dir`, keyed by file name (sorted).
fn dot_files(dir: &Path) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("dot") {
            files.insert(
                path.file_name().unwrap().to_str().unwrap().to_string(),
                std::fs::read_to_string(&path).unwrap(),
            );
        }
    }
    files
}

/// Parse a .dot file with the same graphviz crate the printers emit through,
/// and return (node count, edge count) summed across subgraphs.
fn parse_dot(name: &str, content: &str) -> (usize, usize) {
    let graph = graphviz_rust::parse(content)
        .unwrap_or_else(|e| panic!("{name} is not parseable dot: {e}\n---\n{content}"));
    let stmts = match graph {
        Graph::DiGraph { stmts, .. } => stmts,
        Graph::Graph { .. } => panic!("{name}: expected a digraph"),
    };
    fn count(stmts: &[Stmt], nodes: &mut usize, edges: &mut usize) {
        for stmt in stmts {
            match stmt {
                Stmt::Node(_) => *nodes += 1,
                Stmt::Edge(_) => *edges += 1,
                Stmt::Subgraph(sub) => count(&sub.stmts, nodes, edges),
                _ => {}
            }
        }
    }
    let (mut nodes, mut edges) = (0, 0);
    count(&stmts, &mut nodes, &mut edges);
    (nodes, edges)
}

#[test]
fn cfg_printer_writes_parseable_dot_per_function() {
    let dir = scratch_dir("cfg");
    let output = run_printer(&dir, "cfg");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("CFG for the function"),
        "unexpected stdout: {stdout}"
    );

    let files = dot_files(&dir);
    // One .dot per user-defined function: 9 entrypoints + their 9 wrappers,
    // 2 private helpers and 1 compiler-generated loop function. A floor, not
    // an exact count — compiler bumps may add/remove generated functions.
    assert!(
        files.len() >= 15,
        "expected a .dot per user function, got {}: {:?}",
        files.len(),
        files.keys().collect::<Vec<_>>()
    );

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    for (name, content) in &files {
        assert!(
            content.starts_with("digraph "),
            "{name} does not start with a digraph header"
        );
        // Findings/graphs must stay machine-independent.
        assert!(
            !content.contains(&manifest_dir),
            "{name} leaks an absolute path"
        );
        let (nodes, _) = parse_dot(name, content);
        assert!(nodes >= 1, "{name} has no basic blocks");
    }

    // A function with branches must produce a multi-node CFG with edges.
    let bad2 = &files["reentrancy_reentrancy_TestContract___wrapper__bad2.dot"];
    let (nodes, edges) = parse_dot("__wrapper__bad2", bad2);
    assert!(nodes >= 5, "expected several basic blocks, got {nodes}");
    assert!(edges >= 5, "expected control-flow edges, got {edges}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn callgraph_printer_writes_parseable_dot_per_module() {
    let dir = scratch_dir("callgraph");
    let output = run_printer(&dir, "callgraph");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Call graph for module reentrancy::reentrancy::TestContract"),
        "unexpected stdout: {stdout}"
    );

    let files = dot_files(&dir);
    assert_eq!(
        files.keys().collect::<Vec<_>>(),
        vec!["reentrancy_reentrancy_TestContract.dot"],
        "one callgraph per compilation unit"
    );
    let content = &files["reentrancy_reentrancy_TestContract.dot"];

    let (nodes, edges) = parse_dot("callgraph", content);
    assert!(nodes >= 15, "expected a node per function, got {nodes}");
    assert!(edges >= 15, "expected call edges, got {edges}");

    // Structural spot checks: wrapper -> entrypoint -> helper -> dispatcher.
    for edge in [
        "\"reentrancy::reentrancy::TestContract::__wrapper__bad3\" -> \"reentrancy::reentrancy::TestContract::bad3\"",
        "\"reentrancy::reentrancy::TestContract::bad3\" -> \"reentrancy::reentrancy::TestContract::internal_ext_call\"",
        "\"reentrancy::reentrancy::TestContract::internal_ext_call\" -> \"reentrancy::reentrancy::IAnotherContractDispatcherImpl::foo\"",
    ] {
        assert!(content.contains(edge), "missing edge {edge} in:\n{content}");
    }
    // Functions are clustered into per-module subgraphs.
    for cluster in [
        "subgraph \"cluster_reentrancy::reentrancy::TestContract\"",
        "subgraph \"cluster_reentrancy::reentrancy::IAnotherContractDispatcherImpl\"",
    ] {
        assert!(
            content.contains(cluster),
            "missing {cluster} in:\n{content}"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// Printer output must be run-to-run deterministic (same guarantee detector
/// output has): the callgraph printer used to emit its module subgraphs in
/// HashMap iteration order, which changed on every run.
#[test]
fn printer_output_is_deterministic() {
    for printer in ["cfg", "callgraph"] {
        let dir_a = scratch_dir(&format!("{printer}-det-a"));
        let dir_b = scratch_dir(&format!("{printer}-det-b"));
        run_printer(&dir_a, printer);
        run_printer(&dir_b, printer);
        let files_a = dot_files(&dir_a);
        let files_b = dot_files(&dir_b);
        assert_eq!(
            files_a, files_b,
            "{printer} printer output differs between two identical runs"
        );
        std::fs::remove_dir_all(&dir_a).ok();
        std::fs::remove_dir_all(&dir_b).ok();
    }
}

/// Snapshot of one representative CFG .dot (the smallest stably-named one)
/// so rendering regressions are visible in review.
///
/// NOTE: the node labels embed raw sierra statements, so program-level
/// statement indices and VarIds appear — both are compiler-assigned and WILL
/// churn on compiler bumps. That is acceptable for a printer snapshot
/// (unlike detector messages): review the new rendering and accept it. No
/// machine-specific content (absolute paths, hashes) may ever appear.
#[test]
fn cfg_dot_snapshot() {
    let dir = scratch_dir("cfg-snapshot");
    run_printer(&dir, "cfg");
    let content = std::fs::read_to_string(
        dir.join("reentrancy_reentrancy_TestContract_internal_ext_call.dot"),
    )
    .expect("cfg printer writes internal_ext_call.dot");
    std::fs::remove_dir_all(&dir).ok();
    insta::assert_snapshot!("cfg_internal_ext_call_dot", content);
}

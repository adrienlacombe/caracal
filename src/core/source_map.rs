use std::collections::HashMap;
use std::fmt;
use std::path::{Component, Path};

use cairo_lang_sierra::debug_info::DebugInfo;
use serde_json::Value;

/// Annotation namespace written by the compiler when
/// `CompilerConfig::add_statements_code_locations` is set. Maps every sierra
/// statement index to the Cairo code locations it was generated from.
const STATEMENTS_NAMESPACE: &str = "github.com/software-mansion/cairo-coverage";
/// Annotation namespace written by the compiler when
/// `CompilerConfig::add_functions_debug_info` is set. Maps every sierra
/// function id to (among other things) its Cairo declaration site.
const FUNCTIONS_NAMESPACE: &str = "github.com/software-mansion-labs/cairo-debugger";

/// A position in a Cairo source file of the analyzed target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct SourceLocation {
    /// Path of the `.cairo` file, relative to the analyzed target (the
    /// target's directory for a single-file target, the project root for a
    /// cairo project or Scarb target) and always `/`-separated, so messages
    /// stay portable across machines and OSes. For code from an external
    /// dependency of a Scarb project (which lives under Scarb's cache, at a
    /// machine-specific absolute path) the path is rendered as
    /// `<dep-name>/<path relative to the dependency's package root>`.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column number.
    pub col: usize,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

/// Sierra → Cairo source mapping for one compiled contract, recovered from
/// the debug-info annotations the bundled compiler emits into the contract
/// class. Only available when caracal compiled the source itself: pre-built
/// artifacts (Scarb output, the `starknet-compile` fallback) don't carry
/// these annotations.
///
/// The statement indices are indices into the contract class' sierra
/// program, which is exactly the program caracal analyzes: the compiler
/// builds the class from the very program the debug info was generated for
/// (only ids are rewritten, statements are never reordered), and the
/// felt252 serialization round-trip preserves statement order because
/// branch targets are absolute statement indices.
#[derive(Debug, Default, Clone)]
pub struct SourceMap {
    /// Program-level statement index → location of the user code the
    /// statement was generated from (the outermost inlining call site, i.e.
    /// the same location the compiler itself points diagnostics at).
    statements: HashMap<usize, SourceLocation>,
    /// Numeric sierra function id → declaration site of the function.
    functions: HashMap<u64, SourceLocation>,
}

/// One directory findings may point into, and the prefix its paths are
/// rendered under. The analyzed target itself is the base with an empty
/// prefix; a Scarb dependency (whose sources live under Scarb's cache) gets
/// its package root as the base and `<dep-name>/` as the prefix, so its
/// machine-specific absolute path never leaks into findings.
#[derive(Debug, Clone)]
pub struct SourceBase {
    /// Canonicalized directory locations are relativized against.
    pub root: std::path::PathBuf,
    /// Prepended to the relativized path: empty for the analyzed target,
    /// `<dep-name>/` for a dependency.
    pub prefix: String,
}

impl SourceMap {
    /// Build the mapping from a contract class' debug-info annotations.
    /// `bases` are tried in order; the first whose root contains the file
    /// wins (put the analyzed target first). Locations in files outside
    /// every base (corelib code — including the embedded corelib extracted
    /// under the OS temp dir — or any other machine-specific path) are
    /// dropped so they can never leak into findings.
    pub fn new(debug_info: &DebugInfo, bases: &[SourceBase]) -> Self {
        SourceMap {
            statements: parse_statement_locations(debug_info, bases),
            functions: parse_function_locations(debug_info, bases),
        }
    }

    /// Location of the statement at program-level index `idx`, if it maps to
    /// user code of the analyzed target.
    pub fn statement(&self, idx: usize) -> Option<&SourceLocation> {
        self.statements.get(&idx)
    }

    /// Declaration site of the sierra function with numeric id `id`, if it
    /// maps to user code of the analyzed target.
    pub fn function(&self, id: u64) -> Option<&SourceLocation> {
        self.functions.get(&id)
    }
}

/// Parse the `statements_code_locations` annotation:
/// `{ "<stmt idx>": [[file_path, {start: {line, col}, end: …}, is_macro], …] }`
/// with 0-based lines/cols. Each statement carries its location plus the
/// chain of inlining call sites, innermost first; the last entry is the
/// outermost user-code call site, which is the one the compiler itself uses
/// for diagnostics and the one we report.
fn parse_statement_locations(
    debug_info: &DebugInfo,
    bases: &[SourceBase],
) -> HashMap<usize, SourceLocation> {
    let mut result = HashMap::new();
    let Some(map) = debug_info
        .annotations
        .get(STATEMENTS_NAMESPACE)
        .and_then(|v| v.get("statements_code_locations"))
        .and_then(Value::as_object)
    else {
        return result;
    };
    for (idx, locations) in map {
        let Ok(idx) = idx.parse::<usize>() else {
            continue;
        };
        let Some(entry) = locations.as_array().and_then(|l| l.last()) else {
            continue;
        };
        let (Some(file), Some(span)) = (entry.get(0).and_then(Value::as_str), entry.get(1)) else {
            continue;
        };
        if let Some(location) = to_source_location(file, span, bases) {
            result.insert(idx, location);
        }
    }
    result
}

/// Parse the `functions_info` annotation:
/// `{ "<function id>": { function_file_path, function_code_span: {start: {line, col}, …}, … } }`
/// with 0-based lines/cols. The span covers the whole function; its start is
/// the declaration site.
fn parse_function_locations(
    debug_info: &DebugInfo,
    bases: &[SourceBase],
) -> HashMap<u64, SourceLocation> {
    let mut result = HashMap::new();
    let Some(map) = debug_info
        .annotations
        .get(FUNCTIONS_NAMESPACE)
        .and_then(|v| v.get("functions_info"))
        .and_then(Value::as_object)
    else {
        return result;
    };
    for (id, info) in map {
        let Ok(id) = id.parse::<u64>() else {
            continue;
        };
        let (Some(file), Some(span)) = (
            info.get("function_file_path").and_then(Value::as_str),
            info.get("function_code_span"),
        ) else {
            continue;
        };
        if let Some(location) = to_source_location(file, span, bases) {
            result.insert(id, location);
        }
    }
    result
}

/// Convert one annotation location (file path + 0-based span) into a
/// [`SourceLocation`], relativizing the file against the first base whose
/// root contains it and prepending that base's prefix. Returns `None` for
/// files outside every base — most notably corelib sources, which would
/// otherwise leak the corelib directory (a temp-dir extraction when the
/// embedded corelib is used) into findings.
fn to_source_location(file: &str, span: &Value, bases: &[SourceBase]) -> Option<SourceLocation> {
    let start = span.get("start")?;
    let line = start.get("line")?.as_u64()? as usize;
    let col = start.get("col")?.as_u64()? as usize;

    let path = Path::new(file);
    // The annotation carries the path as the compiler saw it; canonicalize so
    // it compares against the canonicalized base roots (symlinks, `..`,
    // relative targets). Fall back to the lexical path if the file vanished.
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let (relative, prefix) = bases.iter().find_map(|base| {
        canonical
            .strip_prefix(&base.root)
            .ok()
            .map(|rel| (rel, base.prefix.as_str()))
    })?;
    let relative = relative
        .components()
        .filter_map(|c| match c {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if relative.is_empty() {
        return None;
    }
    Some(SourceLocation {
        file: format!("{prefix}{relative}"),
        // The annotations are 0-based, editors and humans are 1-based.
        line: line + 1,
        col: col + 1,
    })
}

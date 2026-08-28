use anyhow::{anyhow, Context, Result};
use include_dir::{include_dir, Dir};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use cairo_lang_starknet_classes::compiler_version::current_compiler_version_id;

/// The corelib matching the pinned compiler, embedded at build time from the
/// vendored `corelib/` tree. Replacing `corelib/` on disk only takes effect
/// after this crate itself is rebuilt (a compiler bump touches `Cargo.toml`,
/// which forces that rebuild anyway).
static VENDORED_CORELIB: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/corelib/src");

/// Resolve the corelib for the bundled in-process compiler.
///
/// Resolution order:
/// 1. the `--corelib` CLI option
/// 2. the `CORELIB_PATH` environment variable
/// 3. the corelib vendored into this binary, extracted to a per-version
///    directory under the OS temp dir
pub fn resolve(cli_option: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(path) = cli_option {
        return Ok(path.clone());
    }
    if let Ok(path) = env::var("CORELIB_PATH") {
        if !path.is_empty() {
            return Ok(path.into());
        }
    }
    vendored_corelib()
}

/// Extract the embedded corelib to `<tmp>/caracal-corelib-<version>/src` and
/// return that `src` path. The directory is reused across runs; extraction
/// goes through a staging directory followed by a rename so a concurrent
/// caracal process never observes a half-written corelib.
fn vendored_corelib() -> Result<PathBuf> {
    let version = current_compiler_version_id();
    let root = env::temp_dir().join(format!("caracal-corelib-{version}"));
    let marker = root.join(".complete");
    let src = root.join("src");
    if marker.exists() {
        return Ok(src);
    }

    let staging = env::temp_dir().join(format!("caracal-corelib-{version}.{}", process::id()));
    if staging.exists() {
        fs::remove_dir_all(&staging).with_context(|| {
            format!(
                "failed to clean the staging directory {}",
                staging.display()
            )
        })?;
    }
    let staging_src = staging.join("src");
    fs::create_dir_all(&staging_src)
        .with_context(|| format!("failed to create {}", staging_src.display()))?;
    VENDORED_CORELIB.extract(&staging_src).with_context(|| {
        format!(
            "failed to extract the bundled corelib to {}",
            staging_src.display()
        )
    })?;
    fs::write(staging.join(".complete"), [])
        .with_context(|| format!("failed to write the marker file in {}", staging.display()))?;

    match fs::rename(&staging, &root) {
        Ok(()) => Ok(src),
        // Another caracal process finished extracting first; use its copy.
        Err(_) if marker.exists() => {
            let _ = fs::remove_dir_all(&staging);
            Ok(src)
        }
        Err(_) => {
            // A stale, incomplete extraction may be in the way; replace it.
            let _ = fs::remove_dir_all(&root);
            match fs::rename(&staging, &root) {
                Ok(()) => Ok(src),
                Err(_) if marker.exists() => {
                    let _ = fs::remove_dir_all(&staging);
                    Ok(src)
                }
                Err(e) => {
                    let _ = fs::remove_dir_all(&staging);
                    Err(anyhow!(e).context(format!(
                        "failed to move the extracted corelib to {}",
                        root.display()
                    )))
                }
            }
        }
    }
}

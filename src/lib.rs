pub mod analysis;
pub mod baseline;
mod compilation;
pub mod config;
pub mod core;
pub mod detectors;
pub mod output;
pub mod printers;
// Public: these are the statement tracers / message builders detectors are
// documented to build findings with, and the integration tests cover them
// through the same API.
pub mod utils;

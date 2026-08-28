use crate::core::core_unit::CoreUnit;
use crate::core::source_map::SourceLocation;

use std::{collections::HashSet, fmt};

pub trait Detector {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn impact(&self) -> Impact;
    fn confidence(&self) -> Confidence;
    fn run(&self, core: &CoreUnit) -> HashSet<Result>;
}

impl fmt::Display for dyn Detector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} | Impact: {} | Confidence: {} | {}",
            self.name(),
            self.impact(),
            self.confidence(),
            self.description()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Impact {
    High,
    Medium,
    Low,
    Informational,
}

impl fmt::Display for Impact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Impact::High => write!(f, "High"),
            Impact::Medium => write!(f, "Medium"),
            Impact::Low => write!(f, "Low"),
            Impact::Informational => write!(f, "Informational"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::High => write!(f, "High"),
            Confidence::Medium => write!(f, "Medium"),
            Confidence::Low => write!(f, "Low"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Result {
    pub impact: Impact,
    pub name: String,
    pub confidence: Confidence,
    pub message: String,
    /// Cairo source location(s) the finding points at, in message order —
    /// e.g. reentrancy findings carry the external call first, then the
    /// write/event. Empty when no source mapping is available (pre-built
    /// artifacts) or the finding has no meaningful anchor. Kept as the last
    /// field so the derived `Ord` still sorts findings by the pre-existing
    /// fields first (snapshot order stability).
    pub locations: Vec<SourceLocation>,
}

impl fmt::Display for Result {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} Impact: {} Confidence: {}\n{}",
            self.name, self.impact, self.confidence, self.message
        )
    }
}

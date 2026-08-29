use super::dataflow::{Analysis, Domain, Forward};
use crate::core::cfg::Cfg;
use crate::core::function::Function;
use crate::core::{basic_block::BasicBlock, function::Type, instruction::Instruction};
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::extensions::core::{CoreLibfunc, CoreType};
use cairo_lang_sierra::extensions::starknet::StarknetConcreteLibfunc;
use cairo_lang_sierra::program::GenStatement;
use cairo_lang_sierra::program_registry::ProgramRegistry;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReentrancyInfo {
    pub external_calls: HashSet<BasicBlock>,
    pub storage_variables_read: HashSet<BasicBlock>,
    pub storage_variables_written: HashSet<BasicBlock>,
    /// Set of variables read before a function call. call -> variables
    pub variables_read_before_calls: HashMap<BasicBlock, HashSet<BasicBlock>>,
    pub events: HashSet<BasicBlock>,
    /// Writes already seen when a call was registered. call -> writes.
    /// On the analyzed function's own CFG write/event ordering is implicit
    /// (writes and events are block-local, so a block's post state can only
    /// pair them with calls from earlier blocks), but the private-call
    /// recursion flattens a whole call tree into one block's state, where a
    /// call would otherwise get paired with writes/events that happened
    /// strictly before it. The detectors skip pairs recorded here.
    pub writes_before_calls: HashMap<BasicBlock, HashSet<BasicBlock>>,
    /// Events already seen when a call was registered. call -> events.
    pub events_before_calls: HashMap<BasicBlock, HashSet<BasicBlock>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReentrancyDomain {
    Bottom,
    Top,
    State(Box<ReentrancyInfo>),
}

impl Domain for ReentrancyDomain {
    fn bottom() -> Self {
        Self::Bottom
    }

    fn top() -> Self {
        Self::Top
    }

    fn join(&mut self, other: &Self) -> bool {
        let res = match (&self, other) {
            // If self is Top or other is Bottom we don't need to do anything
            (Self::Top, _) | (_, Self::Bottom) => return false,
            // The two reentrancy states are the same
            (Self::State(a), Self::State(b)) if a == b => return false,
            // We union the different reentrancy states set
            // Don't union storage_variables_written and events because it will be easier to write the detectors
            // if the values are kept only in the basic block where they happen (not propagated)
            (Self::State(a), Self::State(b)) => {
                let mut new_state = a.clone();
                new_state.external_calls.extend(b.external_calls.clone());
                new_state
                    .storage_variables_read
                    .extend(b.storage_variables_read.clone());
                new_state
                    .variables_read_before_calls
                    .extend(b.variables_read_before_calls.clone());
                new_state
                    .writes_before_calls
                    .extend(b.writes_before_calls.clone());
                new_state
                    .events_before_calls
                    .extend(b.events_before_calls.clone());
                Self::State(new_state)
            }
            // If self is bottom and other is not, clone other in self.
            // Don't clone storage_variables_written and events because it will be easier to write the detectors
            // if the values are kept only in the basic block where they happen (not propagated)
            (Self::Bottom, Self::State(a)) => Self::State(Box::new(ReentrancyInfo {
                external_calls: a.external_calls.clone(),
                storage_variables_read: a.storage_variables_read.clone(),
                storage_variables_written: HashSet::new(),
                variables_read_before_calls: a.variables_read_before_calls.clone(),
                events: HashSet::new(),
                writes_before_calls: a.writes_before_calls.clone(),
                events_before_calls: a.events_before_calls.clone(),
            })),
            _ => Self::Top,
        };

        *self = res;
        true
    }
}

#[derive(Clone, Debug)]
pub struct ReentrancyAnalysis;

impl Analysis for ReentrancyAnalysis {
    type Direction = Forward;
    type Domain = ReentrancyDomain;

    fn bottom_value(&self) -> Self::Domain {
        Self::Domain::Bottom
    }

    fn transfer_function(
        &self,
        basic_block: &BasicBlock,
        state: &mut Self::Domain,
        instruction: &Instruction,
        functions: &[Function],
        registry: &ProgramRegistry<CoreType, CoreLibfunc>,
    ) {
        ReentrancyAnalysis::transfer_function_helper(
            basic_block,
            state,
            instruction,
            functions,
            registry,
            &mut HashSet::new(),
            false,
        );
    }
}

impl ReentrancyAnalysis {
    /// `in_recursion` is true when the instruction belongs to a callee reached
    /// through the private-call recursion below rather than to the function
    /// the engine runs on. The engine's dataflow keeps writes and events
    /// basic-block-local (the join drops them), so on the analyzed function's
    /// own CFG a write/event only shows up in a post state that also contains
    /// a *previous* external call — i.e. only writes/events that happen after
    /// a call are visible to the detectors. The recursion flattens the
    /// callee's basic blocks into a single accumulating state, losing that
    /// ordering; emulate it by recording a write/event only when an external
    /// call was already seen. That guard only orders effects against the
    /// *first* call: a write/event between two calls still lands in the same
    /// flattened state as the later call, so each call registration also
    /// snapshots the writes/events seen so far (`writes_before_calls` /
    /// `events_before_calls`) and the detectors skip those pairs. The
    /// recursion is a single pass in basic-block order, so re-execution
    /// orderings inside loop bodies (a write textually before a call running
    /// again after it) are not modeled — same approximation as
    /// `variables_read_before_calls`.
    #[allow(clippy::too_many_arguments)]
    fn transfer_function_helper(
        basic_block: &BasicBlock,
        state: &mut <ReentrancyAnalysis as Analysis>::Domain,
        instruction: &Instruction,
        functions: &[Function],
        registry: &ProgramRegistry<CoreType, CoreLibfunc>,
        private_functions_seen: &mut HashSet<String>,
        in_recursion: bool,
    ) {
        match state {
            ReentrancyDomain::Bottom => {
                let new_info = ReentrancyInfo::default();
                *state = ReentrancyDomain::State(Box::new(new_info));
            }
            ReentrancyDomain::State(inner_state) => {
                if let GenStatement::Invocation(invoc) = instruction.get_statement() {
                    let lib_func = registry
                        .get_libfunc(&invoc.libfunc_id)
                        .expect("Library function not found in the registry");
                    // Since cairo 2.11+ the storage helpers, dispatcher impls
                    // and event emitters are inlined away, so the effects show
                    // up as raw Starknet syscalls rather than FunctionCall
                    // statements. Recognise them directly.
                    if let CoreConcreteLibfunc::Starknet(sn) = lib_func {
                        match sn {
                            StarknetConcreteLibfunc::StorageRead(_) => {
                                inner_state
                                    .storage_variables_read
                                    .insert(basic_block.clone());
                            }
                            StarknetConcreteLibfunc::StorageWrite(_)
                                if !in_recursion || !inner_state.external_calls.is_empty() =>
                            {
                                inner_state
                                    .storage_variables_written
                                    .insert(basic_block.clone());
                            }
                            StarknetConcreteLibfunc::CallContract(_)
                            | StarknetConcreteLibfunc::LibraryCall(_) => {
                                inner_state.external_calls.insert(basic_block.clone());
                                inner_state.variables_read_before_calls.insert(
                                    basic_block.clone(),
                                    HashSet::from_iter(inner_state.storage_variables_read.clone()),
                                );
                                inner_state.writes_before_calls.insert(
                                    basic_block.clone(),
                                    inner_state.storage_variables_written.clone(),
                                );
                                inner_state
                                    .events_before_calls
                                    .insert(basic_block.clone(), inner_state.events.clone());
                            }
                            StarknetConcreteLibfunc::EmitEvent(_)
                                if !in_recursion || !inner_state.external_calls.is_empty() =>
                            {
                                inner_state.events.insert(basic_block.clone());
                            }
                            _ => {}
                        }
                        return;
                    }
                    if let CoreConcreteLibfunc::FunctionCall(f_called) = lib_func {
                        // We search for the function called in our list of functions to know its type
                        for function in functions {
                            let function_name = function.name();
                            if function_name.as_str()
                                == f_called.function.id.debug_name.as_ref().unwrap()
                            {
                                match function.ty() {
                                    Type::Storage => {
                                        if function_name.ends_with("::read") {
                                            inner_state
                                                .storage_variables_read
                                                .insert(basic_block.clone());
                                        } else if function_name.ends_with("::write")
                                            && (!in_recursion
                                                || !inner_state.external_calls.is_empty())
                                        {
                                            inner_state
                                                .storage_variables_written
                                                .insert(basic_block.clone());
                                        }
                                    }
                                    Type::Event => {
                                        if !in_recursion || !inner_state.external_calls.is_empty() {
                                            inner_state.events.insert(basic_block.clone());
                                        }
                                    }
                                    // External and View are needed because it's possible to call self declared external functions within a private function
                                    Type::Private | Type::Loop | Type::External | Type::View => {
                                        if let GenStatement::Invocation(invoc) =
                                            instruction.get_statement()
                                        {
                                            let lib_func =
                                                registry.get_libfunc(&invoc.libfunc_id).expect(
                                                    "Library function not found in the registry",
                                                );
                                            if let CoreConcreteLibfunc::FunctionCall(f_called) =
                                                lib_func
                                            {
                                                for function in functions {
                                                    let function_name = function.name();
                                                    if function_name.as_str()
                                                        == f_called
                                                            .function
                                                            .id
                                                            .debug_name
                                                            .as_ref()
                                                            .unwrap()
                                                    {
                                                        if private_functions_seen
                                                            .contains(&function_name)
                                                        {
                                                            break;
                                                        }
                                                        private_functions_seen
                                                            .insert(function_name);

                                                        for bb in
                                                            function.get_cfg().get_basic_blocks()
                                                        {
                                                            if let Some(instruction) =
                                                                bb.get_function_call()
                                                            {
                                                                ReentrancyAnalysis::transfer_function_helper(
                                                                    bb,
                                                                    state,
                                                                    instruction,
                                                                    functions,
                                                                    registry,
                                                                    private_functions_seen,
                                                                    true,
                                                                );
                                                            }
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Type::AbiCallContract => {
                                        inner_state.external_calls.insert(basic_block.clone());
                                        inner_state.variables_read_before_calls.insert(
                                            basic_block.clone(),
                                            HashSet::from_iter(
                                                inner_state.storage_variables_read.clone(),
                                            ),
                                        );
                                        inner_state.writes_before_calls.insert(
                                            basic_block.clone(),
                                            inner_state.storage_variables_written.clone(),
                                        );
                                        inner_state.events_before_calls.insert(
                                            basic_block.clone(),
                                            inner_state.events.clone(),
                                        );
                                    }

                                    _ => (),
                                }
                                break;
                            }
                        }
                    }
                }
            }

            ReentrancyDomain::Top => *state = ReentrancyDomain::Top,
        };
    }
}

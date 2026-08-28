use super::function::{Function, Type};
use crate::analysis::taint::Taint;
use crate::analysis::taint::WrapperVariable;
use cairo_lang_sierra::extensions::core::{CoreConcreteLibfunc, CoreLibfunc, CoreType};
use cairo_lang_sierra::ids::VarId;
use cairo_lang_sierra::program::{
    Function as SierraFunction, GenStatement, Program, Statement as SierraStatement,
};
use cairo_lang_sierra::program_registry::ProgramRegistry;
use cairo_lang_starknet_classes::abi::{
    Contract, EventFieldKind, EventKind, Item::Event as AbiEvent, Item::Function as AbiFunction,
    Item::Interface as AbiInterface, Item::L1Handler as AbiL1Handler,
};
use fxhash::FxHashSet;
use std::collections::{HashMap, HashSet};

/// One variant of an ABI event enum, i.e. one emittable event.
pub struct DeclaredEvent {
    /// Full path of the event enum the variant belongs to
    pub enum_path: String,
    /// Index of the variant within the enum — matches the index in the
    /// sierra `enum_init<enum_path, index>` that constructs it
    pub variant_index: usize,
    /// Total number of variants in the enum (flat ones included)
    pub enum_size: usize,
    /// Variant name; `starknet_keccak` of it is the emitted selector key
    pub variant_name: String,
    /// Full path of the variant's event struct type, used for reporting
    pub ty: String,
}

pub struct CompilationUnit {
    /// The compiled sierra program
    sierra_program: Program,
    /// Functions of the program
    functions: Vec<Function>,
    /// Abi of the compiled starknet contracts
    abi: Contract,
    /// Helper registry to get the concrete type from an id
    registry: ProgramRegistry<CoreType, CoreLibfunc>,
    /// Function name to taints
    taint: HashMap<String, Taint>,
}

impl CompilationUnit {
    pub fn new(
        sierra_program: Program,
        abi: Contract,
        registry: ProgramRegistry<CoreType, CoreLibfunc>,
    ) -> Self {
        CompilationUnit {
            sierra_program,
            functions: Vec::new(),
            abi,
            registry,
            taint: HashMap::new(),
        }
    }

    /// Returns all the functions in the Sierra program
    pub fn functions(&self) -> impl Iterator<Item = &Function> {
        self.functions.iter()
    }

    /// Returns the functions that are defined by the user
    /// Constructor - External - View - Private - L1Handler
    pub fn functions_user_defined(&self) -> impl Iterator<Item = &Function> {
        self.functions.iter().filter(|f| {
            matches!(
                f.ty(),
                Type::Constructor
                    | Type::External
                    | Type::View
                    | Type::Private
                    | Type::L1Handler
                    | Type::Loop
            )
        })
    }

    pub fn function_by_name(&self, name: &str) -> Option<&Function> {
        self.functions.iter().find(|f| f.name().as_str() == name)
    }

    /// Declared events, read from the ABI's event-enum items. (The old
    /// implementation scanned for the derived `*IsEvent::append_keys_and_data`
    /// sierra functions, which the compiler inlines away since cairo 2.6.)
    /// Flat variants are skipped — their selector comes from the inner enum's
    /// own variants, not from this variant's name.
    pub fn declared_events(&self) -> Vec<DeclaredEvent> {
        self.abi
            .clone()
            .into_iter()
            .filter_map(|item| match item {
                AbiEvent(e) => match e.kind {
                    EventKind::Enum { variants } => Some((e.name, variants)),
                    _ => None,
                },
                _ => None,
            })
            .flat_map(|(enum_path, variants)| {
                let enum_size = variants.len();
                variants
                    .into_iter()
                    .enumerate()
                    .filter(|(_, v)| v.kind == EventFieldKind::Nested)
                    .map(move |(variant_index, v)| DeclaredEvent {
                        enum_path: enum_path.clone(),
                        variant_index,
                        enum_size,
                        variant_name: v.name,
                        ty: v.ty,
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub fn registry(&self) -> &ProgramRegistry<CoreType, CoreLibfunc> {
        &self.registry
    }

    /// Return true if the variable is tainted i.e. user inputs can control it in some way
    pub fn is_tainted(&self, function_name: String, variable: VarId) -> bool {
        let wrapped_variable = WrapperVariable::new(function_name, variable.id);
        let mut parameters = FxHashSet::default();
        for external_function in self
            .functions
            .iter()
            .filter(|f| matches!(f.ty(), Type::External | Type::L1Handler | Type::View))
        {
            // Since cairo 2.6 the user entrypoint body is inlined into the compiler
            // generated `__wrapper__*`. Its first non-builtin parameter is the raw
            // `Span<felt252>` calldata (not `ContractState`), so every non-builtin
            // parameter here is a user-controlled taint source.
            for param in external_function.params() {
                parameters.insert(WrapperVariable::new(external_function.name(), param.id.id));
            }
        }
        // Get the taint for the function where the variable appear
        let taint = self.taint.get(wrapped_variable.function()).unwrap();
        if taint.taints_any_sources(&parameters, &wrapped_variable) {
            return true;
        }

        false
    }

    /// Return the function_name's Taint if exist.
    /// This can be useful to access to low level taint functions present in Taint
    /// compared to the more general is_tainted
    pub fn get_taint(&self, function_name: &str) -> Option<&Taint> {
        self.taint.get(function_name)
    }

    fn append_function(&mut self, data: SierraFunction, statements: Vec<SierraStatement>) {
        // The compiler adds unsafe_new_contract_state which holds the storage
        // variables, and one generic unsafe_new_component_state::<...> per
        // embedded component; for now we don't consider them. (The component
        // constructor is matched with contains() because its monomorphized
        // name carries a turbofish suffix.)
        let name = data.id.to_string();
        if !name.ends_with("::unsafe_new_contract_state")
            && !name.contains("::unsafe_new_component_state")
        {
            self.functions.push(Function::new(data, statements));
        }
    }

    fn set_functions_type(&mut self) {
        let abi = self.abi.clone();
        for f in self.functions.iter_mut() {
            let full_name = f.name();

            // Corelib storage accessors. When compiling with inlining avoided
            // (cairo >= 2.6 compiled by caracal itself) storage reads/writes
            // appear as calls into the generic corelib storage module instead
            // of raw syscalls or per-variable `InternalContractStateImpl`
            // functions. Classify the read/write entry points as Storage so
            // reads and writes keep being tracked. This must run before the
            // generic `core::` check below.
            if full_name.starts_with("core::starknet::storage")
                && (full_name.ends_with("::read") || full_name.ends_with("::write"))
            {
                f.set_ty(Type::Storage);
                continue;
            }

            // Core library function
            if full_name.starts_with("core::") || full_name.ends_with("::append_keys_and_data") {
                f.set_ty(Type::Core);
                continue;
            }

            // Since cairo 2.6 the user entrypoint body is inlined into the compiler
            // generated `__wrapper__*` function. Treat the wrapper as the user
            // entrypoint and classify it from the ABI.
            if let Some(idx) = full_name.rfind("::__wrapper__") {
                let inner = &full_name[idx + "::__wrapper__".len()..];
                f.set_ty(Self::classify_entrypoint(abi.clone(), inner));
                continue;
            }

            // Pre-2.2 cairo kept __external__/__constructor__/__l1_handler__ wrappers
            // with the body still in a separate inner function. We keep them marked
            // as Wrapper for backwards compatibility with older sierra.
            if full_name.contains("::__external::")
                || full_name.contains("::__constructor::")
                || full_name.contains("::__l1_handler::")
            {
                f.set_ty(Type::Wrapper);
                continue;
            }

            // Contract-scoped storage plumbing generated by the #[storage]
            // macro on cairo >= 2.6: `self.<var>` dereferences ContractState
            // into the storage-base struct through these helpers. They are
            // compiler plumbing, not user code — classify them as Storage so
            // they are excluded from the user-defined function iterators.
            if full_name.ends_with("::StorageStorageMutImpl::storage_mut")
                || full_name.ends_with("::StorageStorageImpl::storage")
                || full_name.ends_with("::ContractStateDerefMut::deref_mut")
                || full_name.ends_with("::ContractStateDeref::deref")
            {
                f.set_ty(Type::Storage);
                continue;
            }

            // Storage variable accessor (generated by the #[storage] macro)
            if full_name.ends_with("::InternalContractStateImpl::address")
                || full_name.ends_with("::InternalContractStateImpl::read")
                || full_name.ends_with("::InternalContractStateImpl::write")
                || full_name.ends_with("::InternalContractMemberStateImpl::address")
                || full_name.ends_with("::InternalContractMemberStateImpl::read")
                || full_name.ends_with("::InternalContractMemberStateImpl::write")
            {
                f.set_ty(Type::Storage);
                continue;
            }

            // ABI dispatcher trait methods
            if full_name.contains("LibraryDispatcherImpl::") {
                f.set_ty(Type::AbiLibraryCall);
                continue;
            }
            if full_name.contains("DispatcherImpl::") {
                f.set_ty(Type::AbiCallContract);
                continue;
            }

            if full_name.contains("::emit::") {
                f.set_ty(Type::Event);
                continue;
            }
            if full_name.ends_with(']') {
                f.set_ty(Type::Loop);
                continue;
            }
            f.set_ty(Type::Private);
        }
    }

    fn classify_entrypoint(abi: Contract, inner_name: &str) -> Type {
        if inner_name == "constructor" {
            return Type::Constructor;
        }
        for item in abi {
            match item {
                AbiFunction(function) if function.name == inner_name => {
                    return match function.state_mutability {
                        cairo_lang_starknet_classes::abi::StateMutability::External => {
                            Type::External
                        }
                        cairo_lang_starknet_classes::abi::StateMutability::View => Type::View,
                    };
                }
                AbiL1Handler(l1h) if l1h.name == inner_name => return Type::L1Handler,
                AbiInterface(iface) => {
                    for item in iface.items.iter() {
                        match item {
                            AbiFunction(function) if function.name == inner_name => {
                                return match function.state_mutability {
                                    cairo_lang_starknet_classes::abi::StateMutability::External => {
                                        Type::External
                                    }
                                    cairo_lang_starknet_classes::abi::StateMutability::View => {
                                        Type::View
                                    }
                                };
                            }
                            AbiL1Handler(l1h) if l1h.name == inner_name => return Type::L1Handler,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        // Not found in ABI: assume external (e.g. private-impl entrypoint, upgrade hook).
        Type::External
    }

    /// Analyze the Sierra program and set the internal data structure
    /// such as create the functions with the corresponding statements
    pub fn analyze(&mut self) {
        // Add the functions in the sierra program
        let funcs = self.sierra_program.funcs.clone();
        let mut funcs_chunks = funcs.windows(2).peekable();

        // There is only 1 function
        if funcs_chunks.peek().is_none() {
            let function = &self.sierra_program.funcs[0];

            self.append_function(
                function.clone(),
                self.sierra_program.statements
                    [function.entry_point.0..self.sierra_program.statements.len()]
                    .to_vec(),
            );
        } else {
            while let Some(funcs) = funcs_chunks.next() {
                if funcs_chunks.peek().is_some() {
                    self.append_function(
                        funcs[0].clone(),
                        self.sierra_program.statements
                            [funcs[0].entry_point.0..funcs[1].entry_point.0]
                            .to_vec(),
                    );
                } else {
                    // Last pair
                    self.append_function(
                        funcs[0].clone(),
                        self.sierra_program.statements
                            [funcs[0].entry_point.0..funcs[1].entry_point.0]
                            .to_vec(),
                    );
                    self.append_function(
                        funcs[1].clone(),
                        self.sierra_program.statements
                            [funcs[1].entry_point.0..self.sierra_program.statements.len()]
                            .to_vec(),
                    );
                }
            }
        }

        self.set_functions_type();

        // Analyze each function
        let mut functions = Vec::with_capacity(self.functions.len());
        functions.clone_from(&self.functions);
        self.functions
            .iter_mut()
            .for_each(|f| f.analyze(&functions, &self.registry));

        // Run analyses on each function after all the functions have been analyzed
        functions.clone_from(&self.functions);
        self.functions
            .iter_mut()
            .for_each(|f| f.run_analyses(&functions, &self.registry));

        // Compute taints
        self.functions.iter().for_each(|f| {
            self.taint
                .insert(f.name(), Taint::new(f.get_statements(), f.name()));
        });

        // Propagate taints to private functions
        self.propagate_taints();
    }

    /// Propagate the taints from external/view/l1_handler functions to private functions
    fn propagate_taints(&mut self) {
        // Collect the arguments of all the external/view/l1_handler functions.
        // View functions are included because their parameters are
        // user-controlled too (`is_tainted` already treats them as sources),
        // and with inlining avoided the user body of a view entrypoint lives
        // in a separate Private function that needs the propagated taint.
        let mut arguments_external_functions: FxHashSet<WrapperVariable> = FxHashSet::default();
        for function in self
            .functions
            .iter()
            .filter(|f| matches!(f.ty(), Type::External | Type::View | Type::L1Handler))
        {
            for param in function.params() {
                arguments_external_functions
                    .insert(WrapperVariable::new(function.name(), param.id.id));
            }
        }

        // There aren't external functions we don't need to propagate anything
        if arguments_external_functions.is_empty() {
            return;
        }

        let mut changed = true;
        // Iterate external, view, l1_handler, private, loop functions and propagate the taints to each private function they call
        // until a fixpoint when no new informations were propagated
        let mut functions_to_check: HashSet<String> = self
            .functions
            .iter()
            .filter(|f| {
                matches!(
                    f.ty(),
                    Type::External | Type::View | Type::L1Handler | Type::Private | Type::Loop
                )
            })
            .map(|f| f.name())
            .collect();

        // We need to use changed and not !functions_to_check.is_empty() because it can contain functions that are never removed
        // such as Core and it would be an infinite loop
        while changed {
            changed = false;

            let functions_to_check_copy = functions_to_check.clone();
            for calling_function in self.functions.iter().filter(|f| {
                functions_to_check_copy.contains(&f.name())
                    && matches!(
                        f.ty(),
                        Type::External | Type::View | Type::L1Handler | Type::Private | Type::Loop
                    )
            }) {
                functions_to_check.remove(&calling_function.name());

                for function_call in calling_function
                    .private_functions_calls()
                    .chain(calling_function.loop_functions_calls())
                {
                    // It will always be an invocation
                    if let GenStatement::Invocation(invoc) = function_call {
                        // The core lib func instance
                        let lib_func = self
                            .registry
                            .get_libfunc(&invoc.libfunc_id)
                            .expect("Library function not found in the registry");

                        // This is always true since private_function_calls contain only FunctionCall statement
                        if let CoreConcreteLibfunc::FunctionCall(f_called) = lib_func {
                            let taint_copy = self.taint.clone();
                            let external_taint = taint_copy.get(&calling_function.name()).unwrap();

                            // Variables used as arguments in the call to the private function
                            let function_called_args: FxHashSet<WrapperVariable> = invoc
                                .args
                                .iter()
                                .map(|arg| WrapperVariable::new(calling_function.name(), arg.id))
                                .collect();

                            // Calling function's parameters

                            for param in calling_function.params() {
                                // If this parameter is ContractState, we don't need to propogate taints
                                if param
                                    .ty
                                    .debug_name
                                    .as_ref()
                                    .unwrap()
                                    .to_string()
                                    .contains("ContractState")
                                {
                                    continue;
                                }
                                // Check if the arguments used to call the private function are tainted by the calling function's parameters
                                for sink in external_taint.taints_any_sinks_variable(
                                    &WrapperVariable::new(calling_function.name(), param.id.id),
                                    &function_called_args,
                                ) {
                                    // If the sink is tainted by some parameters of external functions
                                    // then we need to add those parameters as source for the current sink
                                    for source in external_taint.taints_any_sources_variable(
                                        &arguments_external_functions,
                                        &sink,
                                    ) {
                                        let function_called_name = f_called
                                            .function
                                            .id
                                            .debug_name
                                            .as_ref()
                                            .unwrap()
                                            .to_string();

                                        let private_taint =
                                            self.taint.get_mut(&function_called_name).unwrap();

                                        // The VarId used when calling a function may not have the IDs increasing sequentially
                                        // so to convert the ID we have to iterate the arguments and use the index where we find
                                        // our sink VarId
                                        for (i, var) in invoc.args.iter().enumerate() {
                                            if var.id == sink.variable() {
                                                // We convert the id to be the private function's formal parameter id and not the actual parameter id
                                                let sink_converted = WrapperVariable::new(
                                                    function_called_name.clone(),
                                                    i.try_into().unwrap(),
                                                );

                                                // Add the source i.e. the variable of the external function
                                                if private_taint.add_taint(source, sink_converted) {
                                                    functions_to_check.insert(function_called_name);
                                                    changed = true;
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

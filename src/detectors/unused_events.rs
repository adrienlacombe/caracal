use super::detector::{Confidence, Detector, Impact, Result};
use crate::core::core_unit::CoreUnit;
use crate::utils::filter_builtins_from_signature;
use cairo_lang_sierra::extensions::core::CoreConcreteLibfunc;
use cairo_lang_sierra::program::Statement as SierraStatement;
use cairo_lang_starknet_classes::keccak::starknet_keccak;
use num_bigint::BigInt;
use num_traits::Num;
use std::collections::HashSet;

// Note: It's possible to have FPs when the long syntax to emit events is used
// e.g. self.emit(Event::MyUsedEvent(MyUsedEvent { value: amount }));

// Declared events come from the ABI; emissions are matched three ways:
// - A FunctionCall to the derived `emit` helper, identified by its event
//   parameter type — the pre-cairo-2.6 shape, where those helpers still
//   exist as sierra functions.
// - An `enum_init<EventEnum, variant_index>` anywhere in the user code:
//   since the helpers are inlined, emitting a variant constructs the event
//   enum right at the (inlined) emit site. The derived `append_keys_and_data`
//   match branches for the *other* variants are also inlined there, so the
//   emitted keys can't be identified from the keys array itself — but the
//   enum_init index pins down exactly which variant was built.
// - For a single-variant event enum the compiler folds the enum away
//   entirely (no enum_init, no match) and only the selector key —
//   `starknet_keccak` of the variant name — remains as a felt252 const.
//   Present const == emitted, exact because there is no sibling variant
//   whose inlined branch could carry it.
// An event constructed outside the compilation unit (e.g. received as a
// parameter) produces no enum_init and can thus be a false positive, same
// tolerance as the long-syntax note above.

#[derive(Default)]
pub struct UnusedEvents {}

impl Detector for UnusedEvents {
    fn name(&self) -> &str {
        "unused-events"
    }

    fn description(&self) -> &str {
        "Detect events defined but not emitted"
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn impact(&self) -> Impact {
        Impact::Medium
    }

    fn run(&self, core: &CoreUnit) -> HashSet<Result> {
        let mut results: HashSet<Result> = HashSet::new();
        let compilation_units = core.get_compilation_units();

        for compilation_unit in compilation_units {
            let declared_events = compilation_unit.declared_events();

            // Event types emitted through the derived helpers (legacy shape)
            let mut legacy_emitted: HashSet<String> = HashSet::new();
            // (enum path, variant index) of every enum_init in user code
            let mut enum_inits: HashSet<(String, usize)> = HashSet::new();
            // Every felt252 constant materialized in user code
            let mut felt_consts: HashSet<BigInt> = HashSet::new();

            for f in compilation_unit.functions_user_defined() {
                for event_stmt in f.events_emitted() {
                    if let SierraStatement::Invocation(invoc) = event_stmt {
                        // Get the concrete libfunc called
                        let libfunc = compilation_unit
                            .registry()
                            .get_libfunc(&invoc.libfunc_id)
                            .expect("Library function not found in the registry");

                        if let CoreConcreteLibfunc::FunctionCall(f_called) = libfunc {
                            // The first non builtin argument is the ContractState, the event is the second
                            let event_name = filter_builtins_from_signature(
                                &f_called.signature.param_signatures,
                            )[1]
                            .ty
                            .debug_name
                            .as_ref()
                            .unwrap()
                            .as_str();
                            legacy_emitted.insert(event_name.to_string());
                        }
                    }
                }

                for stmt in f.get_statements() {
                    let SierraStatement::Invocation(invoc) = stmt else {
                        continue;
                    };
                    let Some(libfunc_name) = invoc.libfunc_id.debug_name.as_ref() else {
                        continue;
                    };
                    if let Some(rest) = libfunc_name.strip_prefix("enum_init<") {
                        if let Some((enum_path, index)) = rest
                            .strip_suffix('>')
                            .and_then(|inner| inner.rsplit_once(", "))
                        {
                            if let Ok(index) = index.parse::<usize>() {
                                enum_inits.insert((enum_path.to_string(), index));
                            }
                        }
                    } else if let Some(rest) =
                        libfunc_name.strip_prefix("const_as_immediate<Const<felt252, ")
                    {
                        let value = rest.strip_suffix(">>").and_then(|v| {
                            if let Some(hex) = v.strip_prefix("0x") {
                                BigInt::from_str_radix(hex, 16).ok()
                            } else {
                                BigInt::from_str_radix(v, 10).ok()
                            }
                        });
                        if let Some(value) = value {
                            felt_consts.insert(value);
                        }
                    }
                }
            }

            for event in declared_events.iter() {
                let emitted = legacy_emitted.contains(&event.ty)
                    || enum_inits.contains(&(event.enum_path.clone(), event.variant_index))
                    || (event.enum_size == 1
                        && felt_consts.contains(&BigInt::from(starknet_keccak(
                            event.variant_name.as_bytes(),
                        ))));
                if emitted {
                    continue;
                }
                // We rsplit the event path to get the event name and the module where the event is defined
                let (event_declaration, event_name) = event.ty.rsplit_once("::").unwrap();
                results.insert(Result {
                    name: self.name().to_string(),
                    impact: self.impact(),
                    confidence: self.confidence(),
                    message: format!(
                        "Event {} defined in {} is never emitted",
                        event_name, event_declaration
                    ),
                });
            }
        }
        results
    }
}

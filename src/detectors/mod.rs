use self::detector::Detector;

pub mod block_values_for_randomness;
pub mod controlled_deploy;
pub mod controlled_l1_message;
pub mod controlled_library_call;
pub mod controlled_replace_class;
pub mod dead_code;
pub mod deploy_from_zero;
pub mod detector;
pub mod felt252_overflow;
pub mod privileged_write_no_event;
pub mod read_only_reentrancy;
pub mod reentrancy;
pub mod reentrancy_benign;
pub mod reentrancy_events;
pub mod tx_origin;
pub mod unchecked_l1_handler_from;
pub mod unchecked_transfer;
pub mod unchecked_zero_owner;
pub mod unprotected_replace_class;
pub mod unused_arguments;
pub mod unused_events;
pub mod unused_return;
pub mod use_after_pop_front;

pub fn get_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::<use_after_pop_front::UseAfterPopFront>::default(),
        Box::<controlled_library_call::ControlledLibraryCall>::default(),
        Box::<controlled_replace_class::ControlledReplaceClass>::default(),
        Box::<controlled_deploy::ControlledDeploy>::default(),
        Box::<controlled_l1_message::ControlledL1Message>::default(),
        Box::<unprotected_replace_class::UnprotectedReplaceClass>::default(),
        Box::<deploy_from_zero::DeployFromZero>::default(),
        Box::<block_values_for_randomness::BlockValuesForRandomness>::default(),
        Box::<unchecked_zero_owner::UncheckedZeroOwner>::default(),
        Box::<privileged_write_no_event::PrivilegedWriteNoEvent>::default(),
        Box::<unchecked_transfer::UncheckedTransfer>::default(),
        Box::<unused_events::UnusedEvents>::default(),
        Box::<dead_code::DeadCode>::default(),
        Box::<unused_arguments::UnusedArguments>::default(),
        Box::<unused_return::UnusedReturn>::default(),
        Box::<reentrancy_benign::ReentrancyBenign>::default(),
        Box::<reentrancy::Reentrancy>::default(),
        Box::<reentrancy_events::ReentrancyEvents>::default(),
        Box::<read_only_reentrancy::ReadOnlyReentrancy>::default(),
        Box::<unchecked_l1_handler_from::UncheckedL1HandlerFrom>::default(),
        Box::<felt252_overflow::Felt252Overflow>::default(),
        Box::<tx_origin::TxOrigin>::default(),
    ]
}

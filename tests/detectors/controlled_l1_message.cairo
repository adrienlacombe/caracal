#[starknet::contract]
mod L1MessageContract {
    use starknet::syscalls::send_message_to_l1_syscall;

    #[storage]
    struct Storage {
        l1_bridge: felt252,
    }

    // BAD: the L1 destination address comes straight from calldata.
    #[external(v0)]
    fn bad_direct(ref self: ContractState, to_address: felt252) {
        let payload: Array<felt252> = array![1];
        send_message_to_l1_syscall(to_address, payload.span()).unwrap();
    }

    // BAD: user-controlled destination reaches the syscall through a private
    // helper.
    #[external(v0)]
    fn bad_indirect(ref self: ContractState, to_address: felt252) {
        let _pad = 2_u128; // keep the private helper from being fully inlined
        do_send(to_address);
    }

    fn do_send(to: felt252) {
        let payload: Array<felt252> = array![1];
        send_message_to_l1_syscall(to, payload.span()).unwrap();
    }

    // GOOD: the destination is read from storage; only the payload is user
    // controlled, which is expected.
    #[external(v0)]
    fn good_payload_only(ref self: ContractState, amount: felt252) {
        let to = self.l1_bridge.read();
        let payload: Array<felt252> = array![amount];
        send_message_to_l1_syscall(to, payload.span()).unwrap();
    }
}

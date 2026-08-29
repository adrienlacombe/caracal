#[starknet::contract]
mod PrivilegedWriteNoEvent {
    use starknet::{ContractAddress, get_caller_address};

    #[storage]
    struct Storage {
        owner: ContractAddress,
        fee: u128,
        limit: u128,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        FeeChanged: FeeChanged,
    }

    #[derive(Drop, starknet::Event)]
    struct FeeChanged {
        new_fee: u128,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        assert(!owner.is_zero(), 'zero owner');
        self.owner.write(owner);
    }

    // BAD: an owner-gated configuration write with no event — the change is
    // invisible to off-chain monitoring.
    #[external(v0)]
    fn bad_set_limit(ref self: ContractState, new_limit: u128) {
        assert(get_caller_address() == self.owner.read(), 'not owner');
        self.limit.write(new_limit);
    }

    // BAD: the gate and the write both live in helpers (modifier style);
    // still no event anywhere in the call tree.
    #[external(v0)]
    fn bad_set_limit_indirect(ref self: ContractState, new_limit: u128) {
        assert_only_owner(@self);
        store_limit(ref self, new_limit);
    }

    fn assert_only_owner(self: @ContractState) {
        assert(get_caller_address() == self.owner.read(), 'not owner');
    }

    fn store_limit(ref self: ContractState, new_limit: u128) {
        self.limit.write(new_limit);
    }

    // GOOD: the gated write emits an event.
    #[external(v0)]
    fn good_set_fee(ref self: ContractState, new_fee: u128) {
        assert(get_caller_address() == self.owner.read(), 'not owner');
        self.fee.write(new_fee);
        self.emit(FeeChanged { new_fee });
    }

    // GOOD: the event is emitted inside a helper on the call tree.
    #[external(v0)]
    fn good_set_fee_indirect(ref self: ContractState, new_fee: u128) {
        assert_only_owner(@self);
        store_fee_with_event(ref self, new_fee);
    }

    fn store_fee_with_event(ref self: ContractState, new_fee: u128) {
        self.fee.write(new_fee);
        self.emit(FeeChanged { new_fee });
    }

    // GOOD: an ungated write is not a privileged operation — this detector
    // leaves user-facing state churn alone.
    #[external(v0)]
    fn good_ungated_write(ref self: ContractState, new_limit: u128) {
        self.limit.write(new_limit);
    }

    // GOOD: gated but nothing written — nothing to observe.
    #[external(v0)]
    fn good_gated_no_write(ref self: ContractState) {
        assert(get_caller_address() == self.owner.read(), 'not owner');
    }
}

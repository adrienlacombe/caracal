#[starknet::contract]
mod ReplaceClassContract {
    use starknet::class_hash::ClassHash;
    use starknet::syscalls::replace_class_syscall;

    #[storage]
    struct Storage {
        pending_implementation: ClassHash,
    }

    // BAD: the class hash comes straight from calldata.
    #[external(v0)]
    fn bad_direct(ref self: ContractState, new_class_hash: ClassHash) {
        replace_class_syscall(new_class_hash).unwrap();
    }

    // BAD: user-controlled class hash reaches replace_class through a
    // private helper.
    #[external(v0)]
    fn bad_indirect(ref self: ContractState, new_class_hash: ClassHash) {
        let _pad = 2_u128; // keep the private helper from being fully inlined
        do_replace(new_class_hash);
    }

    fn do_replace(h: ClassHash) {
        replace_class_syscall(h).unwrap();
    }

    // GOOD: class hash is read from storage (operator-controlled, not
    // calldata-controlled).
    #[external(v0)]
    fn good_stored(ref self: ContractState) {
        let stored = self.pending_implementation.read();
        replace_class_syscall(stored).unwrap();
    }
}

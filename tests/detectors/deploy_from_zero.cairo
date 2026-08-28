#[starknet::contract]
mod DeployFromZero {
    use starknet::class_hash::ClassHash;
    use starknet::syscalls::deploy_syscall;

    #[storage]
    struct Storage {
        implementation: ClassHash,
    }

    // BAD: deploy_from_zero is the literal true — the deployed address does
    // not depend on this contract's address, so the (class hash, salt,
    // calldata) tuple can be squatted or griefed by anyone.
    #[external(v0)]
    fn bad_deploy_from_zero(ref self: ContractState, salt: felt252) {
        let h = self.implementation.read();
        let calldata: Array<felt252> = array![];
        deploy_syscall(h, salt, calldata.span(), true).unwrap();
    }

    // GOOD: the flag is the literal false — the deployer address is part of
    // the address computation.
    #[external(v0)]
    fn good_deploy_normal(ref self: ContractState, salt: felt252) {
        let h = self.implementation.read();
        let calldata: Array<felt252> = array![];
        deploy_syscall(h, salt, calldata.span(), false).unwrap();
    }

    // GOOD (under-reporting by design): the flag comes from calldata, so it
    // is not statically determinable and the call is not flagged.
    #[external(v0)]
    fn good_dynamic_flag(ref self: ContractState, salt: felt252, from_zero: bool) {
        let h = self.implementation.read();
        let calldata: Array<felt252> = array![];
        deploy_syscall(h, salt, calldata.span(), from_zero).unwrap();
    }
}

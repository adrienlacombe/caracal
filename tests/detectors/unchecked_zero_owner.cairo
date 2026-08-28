// BAD: the owner address goes straight from the constructor's calldata into
// storage — deploying with a zero owner permanently bricks the access
// control gated on it.
#[starknet::contract]
mod BadOwner {
    use starknet::ContractAddress;

    #[storage]
    struct Storage {
        owner: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
    }
}

// BAD: the unchecked write happens in a private initializer the constructor
// delegates to (the OZ component-initializer shape).
#[starknet::contract]
mod BadOwnerIndirect {
    use starknet::ContractAddress;

    #[storage]
    struct Storage {
        owner: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        let _pad = 2_u128; // keep the initializer from being fully inlined
        init_owner(ref self, owner);
    }

    fn init_owner(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
    }
}

// GOOD: the constructor rejects the zero address before storing
// (Zeroable::is_zero shape).
#[starknet::contract]
mod GoodZeroChecked {
    use starknet::ContractAddress;

    #[storage]
    struct Storage {
        owner: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        assert(!owner.is_zero(), 'zero owner');
        self.owner.write(owner);
    }
}

// GOOD: the zero check is an inequality against a zero-valued address
// (PartialEq shape), and it lives in a private helper.
#[starknet::contract]
mod GoodZeroCheckedIndirect {
    use starknet::ContractAddress;

    #[storage]
    struct Storage {
        owner: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        let _pad = 2_u128; // keep the initializer from being fully inlined
        init_owner(ref self, owner);
    }

    fn init_owner(ref self: ContractState, owner: ContractAddress) {
        assert(owner != 0.try_into().unwrap(), 'zero owner');
        self.owner.write(owner);
    }
}

// GOOD: only ContractAddress parameters are considered — a felt252 that
// happens to be stored is not an owner-shaped parameter.
#[starknet::contract]
mod GoodFeltParam {
    #[storage]
    struct Storage {
        config: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, config: felt252) {
        self.config.write(config);
    }
}

// GOOD: the address parameter is never written to storage (only a value
// stored *under* it), so there is nothing to brick.
#[starknet::contract]
mod GoodAddressAsKey {
    use starknet::ContractAddress;
    use starknet::storage::{Map, StorageMapWriteAccess};

    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u256>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, funder: ContractAddress) {
        self.balances.write(funder, 1_u256);
    }
}

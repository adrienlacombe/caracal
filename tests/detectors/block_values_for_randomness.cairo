#[starknet::contract]
mod BlockValuesForRandomness {
    use core::pedersen::pedersen;
    use core::poseidon::poseidon_hash_span;
    use starknet::{get_block_info, get_block_number, get_block_timestamp};

    #[storage]
    struct Storage {
        last_winner_ticket: felt252,
    }

    // BAD: the block timestamp is hashed — the sequencer picks it and anyone
    // can predict it, so the "random" value is neither.
    #[external(v0)]
    fn bad_timestamp_pedersen(ref self: ContractState, user_seed: felt252) -> felt252 {
        let ts = get_block_timestamp();
        pedersen(ts.into(), user_seed)
    }

    // BAD: block number reduced by modulo — the classic lottery-index
    // pattern.
    #[external(v0)]
    fn bad_number_modulo(ref self: ContractState, participants: u64) -> u64 {
        let bn = get_block_number();
        bn % participants
    }

    // BAD: the timestamp reaches a poseidon hash through array plumbing.
    #[external(v0)]
    fn bad_timestamp_poseidon(ref self: ContractState) -> felt252 {
        let ts = get_block_timestamp();
        let arr: Array<felt252> = array![ts.into()];
        poseidon_hash_span(arr.span())
    }

    // BAD: same weakness through the get_block_info() shape — the value
    // comes out of the BlockInfo struct instead of the direct getter.
    #[external(v0)]
    fn bad_block_info_modulo(ref self: ContractState) -> u64 {
        let info = get_block_info().unbox();
        info.block_timestamp % 100
    }

    // GOOD: comparing the timestamp is a deadline, not randomness.
    #[external(v0)]
    fn good_deadline(ref self: ContractState, deadline: u64) {
        assert(get_block_timestamp() < deadline, 'expired');
    }

    // GOOD: a hash computed in the same function must not be contaminated by
    // an unrelated block value read (used only in a comparison).
    #[external(v0)]
    fn good_hash_unrelated(ref self: ContractState, deadline: u64, user_seed: felt252) -> felt252 {
        assert(get_block_timestamp() < deadline, 'expired');
        pedersen(user_seed, 1)
    }

    // GOOD: dividing a time delta is ordinary time math (epochs, vesting),
    // not randomness.
    #[external(v0)]
    fn good_epoch_division(ref self: ContractState, start: u64) -> u64 {
        let elapsed = get_block_timestamp() - start;
        elapsed / 3600
    }
}

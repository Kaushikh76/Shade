#![cfg(test)]
//! P3 #20 / #23 adversarial tests: a single guardian must not be able to
//! pause or upgrade a target alone when threshold > 1, and an upgrade must
//! not execute before its timelock elapses or after it's been cancelled.

use crate::*;
use soroban_sdk::testutils::{Address as _, Ledger};

/// Records what was called on it — this test module isn't re-verifying
/// Soroban's cross-contract auth semantics (a platform guarantee), only the
/// guardian's own quorum/timelock bookkeeping.
#[contract]
struct MockTarget;

#[contractimpl]
impl MockTarget {
    pub fn pause(env: Env, _reason: BytesN<32>) {
        env.storage().instance().set(&symbol_short!("paused"), &true);
    }
    pub fn unpause(env: Env) {
        env.storage().instance().set(&symbol_short!("paused"), &false);
    }
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.storage().instance().set(&symbol_short!("wasmh"), &new_wasm_hash);
    }
    pub fn is_paused(env: Env) -> bool {
        env.storage().instance().get(&symbol_short!("paused")).unwrap_or(false)
    }
    pub fn wasm_hash(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&symbol_short!("wasmh"))
    }
}

struct Harness {
    env: Env,
    guardian_contract: GovernanceGuardianClient<'static>,
    target: MockTargetClient<'static>,
    target_id: Address,
    g1: Address, g2: Address, g3: Address,
}

fn setup(threshold: u32, delay_ledgers: u32) -> Harness {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let g1 = Address::generate(&env);
    let g2 = Address::generate(&env);
    let g3 = Address::generate(&env);

    let guardian_id = env.register(GovernanceGuardian, ());
    let guardian_contract = GovernanceGuardianClient::new(&env, &guardian_id);
    guardian_contract.initialize(&admin, &Vec::from_array(&env, [g1.clone(), g2.clone(), g3.clone()]), &threshold, &delay_ledgers);

    let target_id = env.register(MockTarget, ());
    let target = MockTargetClient::new(&env, &target_id);

    Harness { env, guardian_contract, target, target_id, g1, g2, g3 }
}

#[test]
fn pause_requires_quorum_not_a_single_guardian() {
    let h = setup(2, 100);
    let reason = BytesN::from_array(&h.env, &[1u8; 32]);

    let id = h.guardian_contract.propose_pause(&h.g1, &h.target_id, &reason, &false);
    assert!(!h.target.is_paused(), "one of two required approvals must not pause the target");

    h.guardian_contract.approve_pause(&h.g2, &id);
    assert!(h.target.is_paused(), "reaching threshold must execute the pause");
}

#[test]
fn duplicate_guardian_approval_rejected() {
    let h = setup(3, 100);
    let reason = BytesN::from_array(&h.env, &[2u8; 32]);
    let id = h.guardian_contract.propose_pause(&h.g1, &h.target_id, &reason, &false);
    let result = h.guardian_contract.try_approve_pause(&h.g1, &id);
    assert!(result.is_err(), "the same guardian approving twice must not double-count toward quorum");
}

#[test]
fn non_guardian_cannot_propose() {
    let h = setup(1, 100);
    let outsider = Address::generate(&h.env);
    let reason = BytesN::from_array(&h.env, &[3u8; 32]);
    let result = h.guardian_contract.try_propose_pause(&outsider, &h.target_id, &reason, &false);
    assert!(result.is_err(), "a non-guardian address must not be able to propose a pause");
}

#[test]
fn upgrade_execution_blocked_before_timelock_elapses() {
    let h = setup(1, 100);
    let new_hash = BytesN::from_array(&h.env, &[7u8; 32]);
    let id = h.guardian_contract.propose_upgrade(&h.g1, &h.target_id, &new_hash);

    let too_early = h.guardian_contract.try_execute_upgrade(&id);
    assert!(too_early.is_err(), "execute_upgrade must fail before the timelock delay has elapsed");
    assert!(h.target.wasm_hash().is_none(), "target must not be upgraded yet");

    h.env.ledger().with_mut(|li| li.sequence_number += 100);
    h.guardian_contract.execute_upgrade(&id);
    assert_eq!(h.target.wasm_hash(), Some(new_hash), "target must be upgraded once quorum + timelock are both satisfied");
}

#[test]
fn cancelled_upgrade_cannot_execute_even_after_timelock() {
    let h = setup(1, 10);
    let new_hash = BytesN::from_array(&h.env, &[9u8; 32]);
    let id = h.guardian_contract.propose_upgrade(&h.g1, &h.target_id, &new_hash);

    h.guardian_contract.cancel_upgrade(&h.g1, &id);
    h.env.ledger().with_mut(|li| li.sequence_number += 100);

    let result = h.guardian_contract.try_execute_upgrade(&id);
    assert!(result.is_err(), "a cancelled upgrade must never execute, no matter how much time passes");
    assert!(h.target.wasm_hash().is_none());
}

#![no_std]
//! GovernanceGuardian: pause/upgrade authority for upgradeable custody contracts
//! (bible: "Timelock for upgrades; immediate pause only for guardian quorum").
//!
//! P3 #20: a prior version of this contract was 36 LOC — a single `guardian`
//! address could pause/unpause instantly with no quorum, and there was no
//! upgrade path at all (contracts like shielded_pool expose their own
//! `upgrade()` gated only by a single admin key, with no timelock — bible
//! Sec "Contract upgrade rule" items #6/#7). This version adds:
//!   - a guardian SET with an admin-configurable M-of-N threshold;
//!   - pause/unpause: no timelock (must stay fast for real incidents), but
//!     requires `threshold` distinct guardian approvals, not one key;
//!   - upgrade: requires `threshold` guardian approvals AND a timelock delay
//!     after quorum is reached before `execute_upgrade` can run — plus
//!     `cancel_upgrade`, so a compromised-but-not-quorum guardian key cannot
//!     force an upgrade through, and a legitimate quorum still has a window
//!     to react to a bad proposal before it takes effect.
//!
//! For this to actually bind a target contract (e.g. shielded_pool), that
//! contract's ADMIN must be this guardian contract's address — Soroban
//! authorizes the immediate calling contract for `Address::require_auth()`
//! with no separate signature, so `pool.upgrade(...)` called from inside
//! `execute_upgrade` satisfies `pool`'s `require_admin()` once `pool`'s admin
//! IS this contract. That is a one-time on-chain `transfer_admin` on the
//! target (see shielded_pool::transfer_admin) — NOT done automatically by
//! deploying this contract, since it's a real, hard-to-reverse action against
//! whatever is already live.
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, vec,
    Address, BytesN, Env, Symbol, Vec,
};

const ADMIN: Symbol = symbol_short!("admin");
const GUARDIANS: Symbol = symbol_short!("guardians");
const THRESHOLD: Symbol = symbol_short!("thresh");
const UPGRADE_DELAY: Symbol = symbol_short!("updelay");
const NEXT_PROPOSAL_ID: Symbol = symbol_short!("nextpid");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    NotGuardian = 2,
    AlreadyApproved = 3,
    ProposalNotFound = 4,
    ThresholdNotMet = 5,
    TimelockNotElapsed = 6,
    AlreadyExecuted = 7,
    InvalidThreshold = 8,
}

fn panic_err(env: &Env, e: Error) -> ! {
    panic_with_error!(env, e)
}

#[contracttype]
#[derive(Clone)]
pub struct PauseProposal {
    pub contract_id: Address,
    pub reason_hash: BytesN<32>,
    pub unpause: bool, // false = pause, true = unpause
    pub approvals: Vec<Address>,
    pub executed: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct UpgradeProposal {
    pub contract_id: Address,
    pub new_wasm_hash: BytesN<32>,
    pub approvals: Vec<Address>,
    pub quorum_at_ledger: Option<u32>, // None until threshold reached; timelock counts from the recorded ledger
    pub executed: bool,
    pub cancelled: bool,
}

#[contracttype]
enum DataKey {
    PauseProposal(u32),
    UpgradeProposal(u32),
}

#[contract]
pub struct GovernanceGuardian;

#[contractimpl]
impl GovernanceGuardian {
    /// `upgrade_delay_ledgers`: minimum ledgers between quorum and execution
    /// for an upgrade proposal (bible item #6, timelock for upgrade execution).
    pub fn initialize(env: Env, admin: Address, guardians: Vec<Address>, threshold: u32, upgrade_delay_ledgers: u32) {
        if env.storage().instance().has(&ADMIN) { panic!("already initialized"); }
        admin.require_auth();
        if threshold == 0 || threshold > guardians.len() { panic_err(&env, Error::InvalidThreshold); }
        env.storage().instance().set(&ADMIN, &admin);
        env.storage().instance().set(&GUARDIANS, &guardians);
        env.storage().instance().set(&THRESHOLD, &threshold);
        env.storage().instance().set(&UPGRADE_DELAY, &upgrade_delay_ledgers);
        env.storage().instance().set(&NEXT_PROPOSAL_ID, &0u32);
    }

    // ---- Role management (admin-gated) ----

    pub fn add_guardian(env: Env, guardian: Address) {
        Self::require_admin(&env);
        let mut guardians = Self::guardians(&env);
        for g in guardians.iter() { if g == guardian { return; } }
        guardians.push_back(guardian);
        env.storage().instance().set(&GUARDIANS, &guardians);
    }

    pub fn remove_guardian(env: Env, guardian: Address) {
        Self::require_admin(&env);
        let guardians = Self::guardians(&env);
        let mut kept = Vec::new(&env);
        for g in guardians.iter() { if g != guardian { kept.push_back(g); } }
        let threshold: u32 = env.storage().instance().get(&THRESHOLD).unwrap_or(1);
        if threshold > kept.len() { panic_err(&env, Error::InvalidThreshold); }
        env.storage().instance().set(&GUARDIANS, &kept);
    }

    pub fn set_threshold(env: Env, threshold: u32) {
        Self::require_admin(&env);
        let guardians = Self::guardians(&env);
        if threshold == 0 || threshold > guardians.len() { panic_err(&env, Error::InvalidThreshold); }
        env.storage().instance().set(&THRESHOLD, &threshold);
    }

    pub fn guardians(env: &Env) -> Vec<Address> {
        env.storage().instance().get(&GUARDIANS).unwrap_or(Vec::new(env))
    }

    pub fn threshold(env: Env) -> u32 {
        env.storage().instance().get(&THRESHOLD).unwrap_or(1)
    }

    // ---- Pause / unpause: quorum required, no timelock ----

    pub fn propose_pause(env: Env, guardian: Address, contract_id: Address, reason_hash: BytesN<32>, unpause: bool) -> u32 {
        Self::require_is_guardian(&env, &guardian);
        guardian.require_auth();
        let id = Self::next_id(&env);
        let proposal = PauseProposal {
            contract_id, reason_hash, unpause,
            approvals: Vec::from_array(&env, [guardian]),
            executed: false,
        };
        env.storage().persistent().set(&DataKey::PauseProposal(id), &proposal);
        Self::try_execute_pause(&env, id, &proposal);
        id
    }

    pub fn approve_pause(env: Env, guardian: Address, proposal_id: u32) {
        Self::require_is_guardian(&env, &guardian);
        guardian.require_auth();
        let mut proposal: PauseProposal = env.storage().persistent().get(&DataKey::PauseProposal(proposal_id))
            .unwrap_or_else(|| panic_err(&env, Error::ProposalNotFound));
        if proposal.executed { panic_err(&env, Error::AlreadyExecuted); }
        for a in proposal.approvals.iter() { if a == guardian { panic_err(&env, Error::AlreadyApproved); } }
        proposal.approvals.push_back(guardian);
        env.storage().persistent().set(&DataKey::PauseProposal(proposal_id), &proposal);
        Self::try_execute_pause(&env, proposal_id, &proposal);
    }

    fn try_execute_pause(env: &Env, id: u32, proposal: &PauseProposal) {
        let threshold: u32 = env.storage().instance().get(&THRESHOLD).unwrap_or(1);
        if proposal.approvals.len() < threshold { return; }
        let method = if proposal.unpause { Symbol::new(env, "unpause") } else { Symbol::new(env, "pause") };
        let args = if proposal.unpause { Vec::new(env) } else { vec![env, proposal.reason_hash.to_val()] };
        let _: () = env.invoke_contract(&proposal.contract_id, &method, args);
        let mut done = proposal.clone();
        done.executed = true;
        env.storage().persistent().set(&DataKey::PauseProposal(id), &done);
        env.events().publish((symbol_short!("pause"), id), (proposal.contract_id.clone(), proposal.unpause));
    }

    // ---- Upgrade: quorum THEN timelock, with cancel ----

    pub fn propose_upgrade(env: Env, guardian: Address, contract_id: Address, new_wasm_hash: BytesN<32>) -> u32 {
        Self::require_is_guardian(&env, &guardian);
        guardian.require_auth();
        let id = Self::next_id(&env);
        let proposal = UpgradeProposal {
            contract_id, new_wasm_hash,
            approvals: Vec::from_array(&env, [guardian]),
            quorum_at_ledger: None, executed: false, cancelled: false,
        };
        env.storage().persistent().set(&DataKey::UpgradeProposal(id), &proposal);
        Self::check_upgrade_quorum(&env, id, proposal);
        id
    }

    pub fn approve_upgrade(env: Env, guardian: Address, proposal_id: u32) {
        Self::require_is_guardian(&env, &guardian);
        guardian.require_auth();
        let mut proposal: UpgradeProposal = env.storage().persistent().get(&DataKey::UpgradeProposal(proposal_id))
            .unwrap_or_else(|| panic_err(&env, Error::ProposalNotFound));
        if proposal.executed || proposal.cancelled { panic_err(&env, Error::AlreadyExecuted); }
        for a in proposal.approvals.iter() { if a == guardian { panic_err(&env, Error::AlreadyApproved); } }
        proposal.approvals.push_back(guardian);
        env.storage().persistent().set(&DataKey::UpgradeProposal(proposal_id), &proposal.clone());
        Self::check_upgrade_quorum(&env, proposal_id, proposal);
    }

    fn check_upgrade_quorum(env: &Env, id: u32, mut proposal: UpgradeProposal) {
        let threshold: u32 = env.storage().instance().get(&THRESHOLD).unwrap_or(1);
        if proposal.quorum_at_ledger.is_none() && proposal.approvals.len() >= threshold {
            proposal.quorum_at_ledger = Some(env.ledger().sequence());
            env.storage().persistent().set(&DataKey::UpgradeProposal(id), &proposal);
            env.events().publish((symbol_short!("upquorum"), id), proposal.contract_id.clone());
        }
    }

    /// Any guardian who approved may cancel before execution — "emergency
    /// pause that cannot steal funds" extends to: a bad upgrade can always be
    /// stopped by the same quorum that could have approved it.
    pub fn cancel_upgrade(env: Env, guardian: Address, proposal_id: u32) {
        Self::require_is_guardian(&env, &guardian);
        guardian.require_auth();
        let mut proposal: UpgradeProposal = env.storage().persistent().get(&DataKey::UpgradeProposal(proposal_id))
            .unwrap_or_else(|| panic_err(&env, Error::ProposalNotFound));
        if proposal.executed { panic_err(&env, Error::AlreadyExecuted); }
        proposal.cancelled = true;
        env.storage().persistent().set(&DataKey::UpgradeProposal(proposal_id), &proposal);
        env.events().publish((symbol_short!("upcancel"), proposal_id), guardian);
    }

    /// Callable by anyone once quorum was reached AND the timelock elapsed —
    /// execution doesn't need to be a guardian action, only proposing/
    /// approving/cancelling does.
    pub fn execute_upgrade(env: Env, proposal_id: u32) {
        let proposal: UpgradeProposal = env.storage().persistent().get(&DataKey::UpgradeProposal(proposal_id))
            .unwrap_or_else(|| panic_err(&env, Error::ProposalNotFound));
        if proposal.executed || proposal.cancelled { panic_err(&env, Error::AlreadyExecuted); }
        let quorum_ledger: u32 = proposal.quorum_at_ledger
            .unwrap_or_else(|| panic_err(&env, Error::ThresholdNotMet));
        let delay: u32 = env.storage().instance().get(&UPGRADE_DELAY).unwrap_or(0);
        if env.ledger().sequence() < quorum_ledger + delay { panic_err(&env, Error::TimelockNotElapsed); }

        let _: () = env.invoke_contract(
            &proposal.contract_id,
            &Symbol::new(&env, "upgrade"),
            vec![&env, proposal.new_wasm_hash.to_val()],
        );
        let mut done = proposal.clone();
        done.executed = true;
        env.storage().persistent().set(&DataKey::UpgradeProposal(proposal_id), &done);
        env.events().publish((symbol_short!("upgraded"), proposal_id), proposal.contract_id);
    }

    pub fn get_pause_proposal(env: Env, id: u32) -> PauseProposal {
        env.storage().persistent().get(&DataKey::PauseProposal(id)).unwrap_or_else(|| panic_err(&env, Error::ProposalNotFound))
    }

    pub fn get_upgrade_proposal(env: Env, id: u32) -> UpgradeProposal {
        env.storage().persistent().get(&DataKey::UpgradeProposal(id)).unwrap_or_else(|| panic_err(&env, Error::ProposalNotFound))
    }

    fn next_id(env: &Env) -> u32 {
        let id: u32 = env.storage().instance().get(&NEXT_PROPOSAL_ID).unwrap_or(0);
        env.storage().instance().set(&NEXT_PROPOSAL_ID, &(id + 1));
        id
    }

    fn require_admin(env: &Env) {
        let admin: Address = env.storage().instance().get(&ADMIN).unwrap_or_else(|| panic_err(env, Error::NotInitialized));
        admin.require_auth();
    }

    fn require_is_guardian(env: &Env, guardian: &Address) {
        let guardians = Self::guardians(env);
        for g in guardians.iter() { if g == *guardian { return; } }
        panic_err(env, Error::NotGuardian);
    }
}

mod tests;

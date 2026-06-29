# Protocol Fixes (phase2.md PHASE 1)

Tracks the protocol/correctness fixes that gate the backend-service and frontend
work. Each is verified on Stellar testnet.

## Current canonical deployment (after security lockdown)

| Contract | ID | Notes |
|---|---|---|
| ShadePool (shielded_pool) | `CAMO3X5C2NDGEGCNZ4AHDIF6U6NBTLSHXXZHZWNSVEIGGTJUBJPAOO6C` | canonical settlement contract |
| NullifierRegistry | `CBAKCITRZLJZFQC4ISSYH5UESYFUYBFRANVM5VPDA6OH3VDTSLQ2IH67` | authorized-spender locked |
| VerifierWithdraw | `CCZ2CM33FDJOELGXBB3E6YYC42VNQ5KKFGCNT4LLIVUT4YEDSNZNLS3D` | admin-gated set_vk |
| VerifierTransfer | `CDBCXL3RLJM7SSZUV2ULCKIKX3FE4KCXRNRFAUXE7PS4YZGDXQSFZ7T5` | admin-gated set_vk |

## Done

### P1.2 — Verifier set_vk locked down (admin-gated + freezable)
`proof_verifiers` now takes an `admin` in the constructor. `set_vk` requires
admin auth and is forbidden once `freeze_vk` is called (one-way immutability for
production). Added `is_frozen`, `admin`.
- On-chain: non-admin `set_vk` rejected (auth failure). PASS.

### P1.3 — NullifierRegistry authorized-spender
`spend(caller, nullifier)` now requires `caller.require_auth()` AND that `caller`
is in an admin-managed authorized-spender set (`set_authorized_spender`). The
ShadePool passes `env.current_contract_address()`; only authorized contracts can
spend. Random accounts cannot grief nullifiers.
- On-chain: random user `spend` rejected (`unauthorized spender` trap). PASS.
- On-chain: authorized pool spends during withdraw — tx
  `2935718c91080dcadc4273360a159fdbf4e9b84c1f949427404d603619ca5254` (the `spend`
  event carries the pool address as caller). PASS.
- Double-spend still reverts (nullifier already spent). PASS.

### P1.10 — Hardcoded local paths removed
All `/Users/...` and `/private/tmp/claude...` absolute paths replaced with the
env-driven `apps/cli/src/lib/paths.ts` module: `SHADE_ROOT` (default
`process.cwd()`), `SHADE_SCRATCH_DIR`, `SHADE_ZK_REF`, `COINUTILS_BIN`,
`CIRCOM2SOROBAN_BIN`, `CIRCUIT_BUILD_DIR`, plus `SHADE_ENV_FILE`. Fresh clones
resolve everything relative to the repo root. `npm run typecheck` passes.

### P1.5 — WithdrawPublic operation binding (recipient/fee/deadline/op-type)
The withdraw circuit now has 10 public signals:
`[nullifierHash, operationType, withdrawnValue, recipientHash, relayerFee,
deadlineLedger, stateRoot, associationRoot, poolId, chainId]`. The contract
`withdraw` enforces:
- `operationType == WITHDRAW_PUBLIC (1)` (else `#11 WrongOperation`)
- `recipientHash == sha256(to_strkey)[:31]` recomputed on-chain (else
  `#12 WrongRecipient`) — a relayer cannot redirect funds
- `relayerFee <= withdrawnValue`; net `value - fee` released to recipient, fee retained
- `deadlineLedger >= current ledger` (else `#13 Expired`)

On-chain proof (current pool `CCTVKHRPFH3GGUMXWJ3B3KFOGTU6YG3WV263MRK5UL5ELIADA2IVNGTK`):
- Withdraw tx `bcaf316a4d13d0b9ea79bd7756fdad020fff478814efb4a4dc34f2cd59868172`
  — net 4900000 (= 5000000 - 100000 fee) released; recipientHash matched. PASS.
- Relayer redirect to a different recipient rejected with `Error(Contract, #12)`. PASS.
This is Definition-of-Done #4 ("Withdraw proof binds recipient").

NOTE: withdraw/rfq_settle/withdraw_cctp share this 10-signal circuit; the latter
two now read the new indices (value@2, stateRoot@6, assoc@7, pool@8, chain@9) so
they keep working, but their FULL term binding is P1.6/P1.7 (below).

## Remaining PHASE 1 (next)

- **P1.6 — RFQ settlement binding:** bind quote_hash, intent_hash, output asset,
  fee, solver into the proof; contract enforces arg==proof. (Definition-of-Done #6.)
- **P1.7 — WithdrawCCTP binding:** bind destination_domain, destination_recipient,
  max_fee, finality_threshold, deadline. (Definition-of-Done #5 for exit.)
- **P1.8 — deposit_note_mint circuit** binding the CCTP message to the note.
- **P1.4/8 — deposit_note_mint circuit** binding the CCTP message to the note.
- **P1.1 — Canonical naming:** document `shielded_pool` as `ShadePool` and mark
  legacy `ShadeVault`/`CommitmentTree` deprecated (not on the active path).
- **P1.9 — Root auditor service** (recompute lean-imt root from events, compare
  on-chain, flag `ROOT_MISMATCH_CRITICAL`).
- **P1.11 — Fresh `docs/test-report.generated.md`** per run + archive old; fail
  on `FAIL`.

## Then PHASES 2-7 (multi-session)
Real API endpoints, relayer/prover/solver/root-auditor services + queue, wallet
auth + user DB, Docker for every process, Next.js frontend, app-level e2e.

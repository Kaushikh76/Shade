# Testnet E2E — Acceptance Suite

> **Testnet only. Do not use with real funds. No mainnet custody claim.**
> Remittance is simulated only. RFQ is the current USDC→XLM route unless the MPC
> priced crossing (Phase 6) is green.

This document tracks the single reproducible acceptance command required by
`shade_testnet_e2e_agent_build_spec.md` §0.7 / §12.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run typecheck` | TypeScript typecheck (all apps/packages). |
| `npm run test:ts` | Backend unit/integration tests (self-contained; no DB/testnet). |
| `npm run test:contracts` | Rust soroban workspace tests + standalone `lean_imt` crate. |
| `npm run test:circuits` | Circom witness/proof tests (real Groth16 verify). |
| `npm run test` | `test:ts` + `test:contracts` + `test:circuits`. |
| `npm run test:security` | Security regression tests + static forbidden-pattern gates. |
| `npm run ci:full` | `typecheck` + `test` + `security:gates` (the PR gate, runnable locally). |
| `npm run e2e:testnet:all` | The testnet acceptance matrix (§12.2 functional + §12.3 adversarial). |

## `e2e:testnet:all`

`e2e:testnet:all` runs the full scenario matrix. Each scenario reports one of:

- `PASS` — scenario asserted real testnet state.
- `FAIL` — scenario ran and failed.
- `NOT_IMPLEMENTED` — the phase that owns this scenario is not yet built
  (spec §4.5). No mock-success fallback (spec §0.3).
- `SKIPPED_NO_TESTNET` — testnet config not present; the on-chain assertion
  could not run. This still fails the gate — acceptance must assert real state.

The command exits non-zero unless **every required** scenario is `PASS`. Until
all phases land it fails with a clear incomplete-task list.

### Testnet prerequisites

The on-chain scenarios require deployed testnet contracts and funded keys:

```bash
export SHADE_TESTNET_READY=true
export STELLAR_RPC_URL=...            # Soroban testnet RPC
export SHIELDED_POOL_CONTRACT_ID=...  # deployed pool contract id
# plus funded relayer/solver/user keys via .env.generated (see scripts/setup-env.ts)
```

The circuit tests additionally require the external ZK reference (coinutils
prover + ptau) at `.zk-ref/soroban-examples/privacy-pools` (gitignored; override
with `SHADE_ZK_REF`). In CI set the `SHADE_ZK_REF_URL` repo variable.

## Scenario matrix (owning phase)

Functional (§12.2): F1 CCTP inbound (P4), F2 public withdraw (P2), F3 RFQ
USDC→XLM (P3), F4 MPC same-asset (P5), F5 CCTP exit (P4), F6 remit simulated
(P7), F7 Shade View (P7), F8 recovery (P7), F9 MPC priced cross-asset (P6,
optional).

Adversarial (§12.3): duplicate CCTP nonce, expired quote, relayer mutates
destination/amount/asset, solver fee change, wrong ASP root, denied compliance
label, forged tree root, duplicate/threshold committee, missing proof, verifier
unset, wrong batch hash, wrong output commitment, wrong asset id, double spend.

## CI

`.github/workflows/ci.yml` runs on every PR: `typecheck-and-test`, `security`,
`secret-scan`, `contracts` (build + tests), and `circuits`. The
`nightly-testnet` job runs `e2e:testnet:all` on a schedule with testnet secrets.

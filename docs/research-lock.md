# Research Lock

Locked on: 2026-06-29

This document is the gate before protocol implementation. Facts below were checked against official documentation during this build pass.

## Circle CCTP

- CCTP version: V2.
- CCTP domains are Circle-issued identifiers, not chain IDs. Arbitrum is domain `3`; Stellar is domain `27`.
- Circle's supported-chain table lists Stellar as a CCTP source with standard transfer support and notes that Stellar address encoding and USDC precision require special handling.
- Testnet support follows listed mainnet support; official docs state that if a mainnet is listed, its official testnet is also supported.
- Official source: https://developers.circle.com/cctp/concepts/supported-chains-and-domains

## Arbitrum Sepolia

- Chain ID: `421614`.
- CCTP domain: `3`.
- Testnet USDC address: `0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d`.
- TokenMessengerV2: `0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA`.
- MessageTransmitterV2: `0xE737e5cEBEEBa77EFE34D4aa090756590b1CE275`.
- TokenMinterV2: `0xb43db544E2c27092c107639Ad201b3dEfAbcF192`.
- Official sources:
  - https://developers.circle.com/stablecoins/usdc-contract-addresses
  - https://developers.circle.com/cctp/references/contract-addresses

## Stellar Testnet CCTP

- CCTP domain: `27`.
- TokenMessengerMinter: `CDNG7HXAPBWICI2E3AUBP3YZWZELJLYSB6F5CC7WLDTLTHVM74SLRTHP`.
- MessageTransmitter: `CBJ6MTCKKZG73PMDZCJMSFRD7DQEMI4FKDH7CGDSV4W6FHCRBCQAVVJY`.
- CctpForwarder: `CA66Q2WFBND6V4UEB7RD4SAXSVIWMD6RA4X3U32ELVFGXV5PJK4T4VSZ`.
- Stellar Testnet USDC asset: `USDC-GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5`.
- Official source: https://developers.circle.com/cctp/references/stellar-contracts

## CCTP Attestation API

- Sandbox Iris base selected for testnet: `https://iris-api-sandbox.circle.com`.
- The code uses Circle's V2 message lookup shape and keeps raw message parsing required for Stellar address fields.
- This must be rechecked before live acceptance if Circle changes the endpoint path or API shape.
- Official source: https://developers.circle.com/cctp

## Stellar Network And Tooling

- Stellar Testnet RPC URL: `https://soroban-testnet.stellar.org`.
- Stellar Testnet Horizon URL: `https://horizon-testnet.stellar.org`.
- Stellar Testnet passphrase: `Test SDF Network ; September 2015`.
- Friendbot URL: `https://friendbot.stellar.org`.
- Friendbot funds new accounts with 10,000 fake XLM and is rate limited.
- Stellar CLI latest stable release in docs: `v27.0.0`.
- Install command: `brew install stellar-cli` or `curl -fsSL https://github.com/stellar/stellar-cli/raw/main/install.sh | sh`.
- Rust contract target: `wasm32v1-none`.
- Official sources:
  - https://developers.stellar.org/docs/networks
  - https://developers.stellar.org/docs/build/smart-contracts/getting-started/setup

## Soroban ZK Path

- Stellar Protocol 25 introduced BN254 and Poseidon/Poseidon2 host functions.
- BN254 host functions include `g1_add`, `g1_mul`, and `pairing_check`.
- Poseidon host functions include `poseidon` and `poseidon2`.
- Stellar docs point to Noir Ultrahonk Soroban verifier examples, but warn that these primitives are building blocks, not a full privacy system.
- Phase implementation selects Noir/BN254 if the verifier example and SDK build cleanly with the installed toolchain. If not, the fallback is Circom/Groth16 using BN254 host functions.
- Official source: https://developers.stellar.org/docs/build/apps/zk

## Stellar CCTP Footguns

- Stellar CCTP message fields use raw 32-byte address payloads and omit the `G`, `M`, or `C` strkey type marker.
- `mintRecipient` is assumed to be a contract address on Stellar.
- For inbound transfers to a Stellar user/account/contract recipient, use CctpForwarder.
- On the source burn, set both `mintRecipient` and `destinationCaller` to the CctpForwarder contract.
- Hook data must encode `forwardRecipient` as a Stellar strkey.
- If `destinationCaller` is wrong or `mintRecipient` is not the forwarder, funds can become permanently stuck.
- CCTP message amounts are six-decimal subunits. Stellar displays/sees seven-decimal USDC subunits; destination mint scales by 10.
- Official source: https://developers.circle.com/cctp/references/stellar

## Current Local Blockers

- `stellar` CLI is not installed in this environment, so contract build/deploy and real Stellar e2e cannot be completed locally yet.
- `.env` with `ARB_SEPOLIA_PRIVATE_KEY` and `ARB_SEPOLIA_RPC_URL` was not present at the start of this run, so live Arbitrum balance validation and burns cannot run.

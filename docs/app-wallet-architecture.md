# Shade App Wallet Architecture

Canonical model for the Phase-2 product (per `audit.md`). Supersedes the earlier
custom-wallet-nonce auth as the *app* identity layer.

## Identity & wallets

- **Privy is the canonical app identity layer.** The **Privy DID** (`privy_user_id`)
  is the canonical user identity. The backend verifies the Privy access token
  (ES256 JWT) on every user-owned route and derives identity from the token — never
  from client-supplied ids.
- **EVM wallet = funding wallet, not the Shade account.** A user links an EVM
  wallet (Privy embedded or external) to fund deposits; losing/rotating it does not
  lose the Shade account or notes.
- **Stellar wallet is optional for deposit.** It is required today only for spends
  that hit the contract's `to.require_auth()` (`withdraw`, `withdraw_cctp`). Those
  are signed **client-side** via Freighter (active) or Privy Stellar Tier-2 raw
  signing (TODO — Privy Stellar is Tier 2, so no end-to-end tx helper exists).
- A future **proof-authorized relayer path** (`withdraw_by_proof` /
  `withdraw_cctp_by_proof`, no `require_auth`) removes the need for a user Stellar
  wallet on EVM exits. Until then, the active Stellar signer is Freighter.

## Recovery hierarchy (note vault)

Notes are private; losing them = losing funds. Recovery is built on a **random
`vault_master_key`** generated in the browser, never on raw EVM signature bytes.
The master key is **wrapped** (not stored) by:

1. **Passkey / WebAuthn PRF** — primary, when available.
2. **Stellar Ed25519 signature** (Freighter `signMessage`, or Privy Stellar raw) —
   secondary.
3. **Recovery-kit passphrase** (Argon2id/scrypt/PBKDF2) — mandatory downloadable
   fallback.
4. **EVM signature** — **diagnostic-only**; can never satisfy the recovery policy
   by itself (`ALLOW_EVM_SIGNATURE_ONLY_RECOVERY=false`).

**No vault backup verified + recovery policy sufficient → no deposit.**

## Backend trust boundary

The backend stores only:
- encrypted vault ciphertext + AAD,
- wrapped key blobs + wrapper metadata (no key material),
- user/wallet/activity records.

The backend **never** sees plaintext notes, note secrets, the vault master key,
derived wrapper keys, or user private keys. Envelopes containing any plaintext
note/secret/key field are rejected (see `docs/note-vault-recovery.md`).

## Operator keys (allowed in server env)

Only protocol-operator wallets may live in server env: the **relayer** (Stellar
admin/registrar), **solver** (Arbitrum fills + ed25519 quote signing), and
**deployer**. Normal user deposits do **not** use `ARB_SEPOLIA_PRIVATE_KEY` /
`ETH_PRIVATE_KEY` (the burn is user-signed) and normal user spends do **not** use
`STELLAR_USER_SECRET` (the Soroban tx is user-signed). The legacy operator-driven
testnet deposit remains only behind `ENABLE_OPERATOR_TESTNET_DEPOSIT=false` for
dev/test and is never called by app routes.

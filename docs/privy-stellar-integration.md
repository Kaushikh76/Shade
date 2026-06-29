# Privy + Stellar Integration

Verified against current docs (see `docs/research-lock-phase2-wallets.md`).

## Privy as identity

- Frontend uses the Privy React SDK; users log in with Privy (email/social/wallet).
- Privy issues an **access token** (ES256 JWT) sent to the backend as the
  `privy-token` cookie or `Authorization: Bearer`.
- Backend (`packages/auth-privy`) verifies it with the dashboard **JWT
  verification key** (ES256 public key) — offline, no network call — and treats
  `sub`/`userId` (the **Privy DID**) as `privy_user_id`. `requirePrivyUser`
  rejects unauthenticated/expired tokens (401) on all user-owned routes; only
  `/health`, `/v1/config`, `/v1/contracts`, `/v1/public/*` are public.
- `ENABLE_LEGACY_WALLET_AUTH` (default `false`) keeps the old custom
  nonce/signature auth as a dev fallback only.

## Why Stellar needs custom signing (Tier 2)

Privy supports Stellar at **Tier 2** = curve-level Ed25519 signing only, with no
end-to-end transaction build/submit helper (that is Tier 3, EVM/Solana/Tempo).
So Shade must:

1. Build the Soroban transaction (Stellar SDK) on the **backend** and return XDR.
2. Have the **client** sign it with a Stellar signer.
3. Submit the signed XDR — **no user Stellar secret touches the backend.**

### Active signer: Freighter (`@stellar/freighter-api`)

- `isConnected()` → `requestAccess()` → `{address}`; `getNetworkDetails()` for the
  passphrase + Soroban RPC.
- `signTransaction(xdr, {networkPassphrase, address})` → `{signedTxXdr,
  signerAddress}`; for Soroban auth flows, `signAuthEntry(entryXdr, {address})`.
- `signMessage(message, {address})` → `{signedMessage}` is used for the **Stellar
  Ed25519 vault-recovery wrapper** signature.
- Submit: `TransactionBuilder.fromXDR(signedTxXdr, passphrase)` → Soroban RPC
  `sendTransaction`.

### Privy Stellar (Tier 2): TODO

Privy Stellar raw signing can produce the Ed25519 signature for an arbitrary
payload, but the public docs don't pin the exact raw-sign method for Tier-2
chains. Until that is confirmed, **Freighter is the active Stellar signer** and
Privy Stellar raw signing is documented as a TODO. The frontend gracefully falls
back to Freighter.

## Spend paths

- **Path A (current contract):** `withdraw` / `withdraw_cctp` call
  `to.require_auth()`, so the user's Stellar wallet must sign. Backend builds XDR,
  Freighter signs, backend broadcasts.
- **Path B (preferred, future):** `withdraw_by_proof` / `withdraw_cctp_by_proof`
  entrypoints that do NOT call `require_auth` and rely entirely on the already-bound
  proof public inputs (op-type, recipient/destination, amount, fee, deadline,
  pool/chain id, nullifier). The relayer submits; the user needs no Stellar wallet
  for an EVM exit. Tracked in `docs/blockers.md`.

Normal app routes never use `STELLAR_USER_SECRET` or a `toSecret`.

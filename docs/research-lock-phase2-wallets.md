# Research Lock — Phase 2 Wallets / Privy / Note Vault

> Gating artifact for `audit.md` PHASE 0. Verified against official docs on
> 2026-06-30 before any wallet/Privy/note-vault code was written. Records what was
> confirmed and the exact APIs the implementation relies on.

## 1. Privy — access-token verification (backend)

- Privy access tokens are **JWTs signed with ES256**. Claims: `sub` = the user's
  **Privy DID** (canonical identity), `aud` = app id, `iss` = `privy.io`, `exp`,
  `sid` (session id).
- Sent to the backend as either the **`privy-token` cookie** or
  `Authorization: Bearer <token>`.
- Verify with the server SDK:
  - `@privy-io/server-auth`: `new PrivyClient(appId, appSecret)` →
    `privy.verifyAuthToken(token, verificationKey?)` → `AuthTokenClaims`
    (`appId`, `userId` = DID, `issuer`, `issuedAt`, `expiration`, `sessionId`).
  - `@privy-io/node` (newer): `new PrivyClient({appId, appSecret, jwtVerificationKey})`
    → `privy.utils().auth().verifyAccessToken({access_token})`.
  - **Offline / no-network path (what we use as the verifiable default):** the JWT
    is plain ES256; verify with `jose.jwtVerify(token, publicKey, {issuer:'privy.io',
    audience: appId})` using the **JWT verification key** copied from Privy
    Dashboard → Configuration → App settings (a PEM SPKI public key). This avoids a
    network round-trip and is unit-testable with a locally-minted ES256 token.
- Decision: backend treats **Privy DID (`sub`/`userId`) as the canonical
  `privy_user_id`**. Never trust `user_id`/`wallet_address` from the client body —
  always derive identity from the verified token and check ownership in the DB.
- Sources: https://docs.privy.io/authentication/user-authentication/access-tokens ,
  https://docs.privy.io/guide/server/authorization/verification ,
  https://www.npmjs.com/package/@privy-io/server-auth

## 2. Privy — wallet tiers & Stellar support

- **Tier 3 (full SDK: tx build + submit):** Ethereum/EVM, Solana/SVM, Tempo.
- **Tier 2 (wallet abstractions: curve-level signatures, address derivation, NO
  end-to-end tx helpers):** **Stellar** (also Bitcoin, Cosmos, Sui, Tron, Near,
  Ton, Starknet, Aptos, Movement, Spark).
- **Tier 1:** raw cryptographic signatures only.
- Consequence for Shade: **Privy Stellar is Tier 2** → there is no Privy helper to
  build+submit a Soroban transaction. Custom Stellar transaction building (Stellar
  SDK) plus raw Ed25519 signing through Privy is required, OR use Freighter. We
  treat **Freighter as the active Stellar signer** and Privy Stellar raw signing as
  a documented TODO (the Tier-2 raw-sign method name is not pinned in public docs).
- Sources: https://docs.privy.io/wallets/overview ,
  https://docs.privy.io/wallets/overview/chains

## 3. Freighter — `@stellar/freighter-api` (Stellar signer)

Newer API returns objects `{value, error}` (not bare strings):
- `isConnected()` → `{isConnected, error?}` (extension installed?)
- `isAllowed()` / `setAllowed()` → `{isAllowed, error?}` (dapp allow-list)
- `requestAccess()` → `{address, error?}` (authorize + return pubkey, prompts)
- `getAddress()` → `{address, error?}` (non-prompting)
- `getNetwork()` → `{network, networkPassphrase, error?}`
- `getNetworkDetails()` → `{network, networkUrl, networkPassphrase, sorobanRpcUrl?, error?}`
- `signTransaction(xdr, {network|networkPassphrase, address})` →
  `{signedTxXdr, signerAddress, error?}`
- `signAuthEntry(entryXdr, {address})` → `{signedAuthEntry, signerAddress, error?}`
  (Soroban auth flows)
- `signMessage(message, {address})` → `{signedMessage, signerAddress, error?}`
  (SEP-53). **We use `signMessage` to produce the Stellar Ed25519 vault-recovery
  wrapper signature.**
- Submit flow: `signTransaction` → `TransactionBuilder.fromXDR(signedTxXdr,
  passphrase)` → submit via Soroban RPC `sendTransaction`. **No user secret ever
  touches the backend** — the backend builds the XDR, the wallet signs, the backend
  (or client) broadcasts.
- Source: https://docs.freighter.app/llms-full.txt (extension API)

## 4. WebAuthn PRF (passkey primary recovery wrapper)

- The **PRF extension** is a per-credential random oracle: same input salt →
  same 32-byte output, bound to that passkey. Ideal as a key-wrapping secret.
- Create: `publicKey.extensions.prf = { eval: { first: <salt bytes> } }`;
  read `cred.getClientExtensionResults().prf` → `{enabled, results:{first}}`.
  `enabled` may be false at creation on some authenticators → derive at first
  assertion instead.
- Assert: `extensions.prf = { evalByCredential: { "<b64url credId>": { first:
  salt } } }`; read `getClientExtensionResults().prf.results.first`.
- The PRF output is used as HKDF input key material to derive an AES-GCM wrapping
  key; we wrap the random `vault_master_key` with it. Mixing `eval` and
  `evalByCredential`, or `eval` in `get()`, throws `NotSupportedError`.
- `credProps`/authenticator-data flags: **be** (backup eligible) and **bs**
  (backup state) tell us whether the passkey is synced/recoverable — stored in
  wrapper metadata to inform recovery-policy strength. Support is uneven across
  browsers/authenticators (assertion-time PRF is better supported than
  creation-time) → PRF is the *primary* wrapper but never the *only* one.
- Sources: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions
  (PRF + credProps)

## 5. Stellar CCTP (already in-repo, re-confirmed)

- Inbound: Arbitrum Sepolia `depositForBurnWithHook` → Circle attestation →
  Stellar CCTP **Forwarder** `mint_and_forward(message, attestation)` mints USDC to
  the `forwardRecipient` (ShadePool) via the hook. mintRecipient + destinationCaller
  MUST be the Forwarder contract; hook `forwardRecipient` = ShadePool.
- Addresses are pinned in `packages/cctp-utils` `LOCKED_CCTP` (Arbitrum domain 3,
  Stellar domain 27, TokenMessenger, MessageTransmitter, Forwarder, USDC SAC).
- This is unchanged; the Phase-6 work moves the **burn signature from a backend
  EVM key to the user's wallet** and adds backend validation of the burn tx.

## Architecture decisions locked by this research

1. **Privy DID is the canonical user identity.** Backend verifies the Privy access
   token (ES256/JWKS) on every user-owned route; client-supplied ids are never
   trusted.
2. **EVM wallet = funding wallet only.** The Shade account ≠ an EVM key.
3. **Stellar wallet is optional for deposit**, required today only for
   `to.require_auth()` spends — signed client-side via **Freighter** (active) or
   Privy Stellar Tier-2 raw signing (TODO). Path B (`*_by_proof` relayer
   entrypoints, no `require_auth`) is the preferred future path.
4. **Note recovery uses a random `vault_master_key`**, never raw EVM signature
   bytes. The master key is **wrapped** by: passkey PRF (primary), Stellar Ed25519
   signature (secondary), recovery-kit passphrase (mandatory fallback, Argon2id/
   scrypt/PBKDF2 KDF). EVM-signature wrapper is **diagnostic-only** and can never
   satisfy the recovery-policy minimum.
5. **Backend stores only ciphertext + wrapped keys.** It must reject envelopes
   containing any plaintext note/secret/key field. No deposit without a verified
   vault backup + sufficient recovery policy.

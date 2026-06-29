# Shade Note Vault & Recovery

How private notes survive a browser-cache wipe without the backend ever seeing
plaintext. Implemented in `packages/note-vault` (browser-safe WebCrypto).

## Key model

1. Browser generates a **random 256-bit `vault_master_key`** (WebCrypto).
2. The vault plaintext (note preimages + metadata) is encrypted with the master
   key using **AES-256-GCM**, bound to **AAD** (app, origin, vault_id,
   privy_user_id, vault_version) so ciphertext cannot be replayed under a different
   identity/origin.
3. The master key is **wrapped** by one or more recovery methods. Each wrapper
   stores only `wrapped_key = AES-GCM(derived_wrapper_key, vault_master_key)` plus a
   per-wrapper salt and non-secret metadata. The wrapper keys themselves are derived
   client-side and never stored.

To restore: fetch the encrypted envelope, unwrap the master key with any one
wrapper, decrypt the vault, repopulate notes in memory / encrypted IndexedDB.

## Wrappers

| Wrapper | KDF / source | Role | Notes |
|---|---|---|---|
| `passkey_prf` | HKDF over WebAuthn PRF output | Primary | needs authenticator PRF support; metadata records be/bs backup flags |
| `stellar_ed25519_signature` | HKDF over a deterministic Stellar `signMessage` signature | Secondary | Freighter or Privy Stellar |
| `recovery_kit_password` | Argon2id/scrypt/PBKDF2 over a user passphrase | Mandatory fallback | downloadable recovery kit file |
| `evm_signature` | HKDF over an EVM personal_sign | **diagnostic-only** | `diagnostic_only:true`; cannot satisfy policy alone |

## Recovery policy

- **Testnet:** at least **1 non-EVM** wrapper before deposit
  (`SHADE_MIN_RECOVERY_WRAPPERS_TESTNET=1`).
- **Mainnet:** at least **2** wrappers, one of which is passkey-PRF or
  Stellar-Ed25519, plus a recovery kit or second independent method
  (`SHADE_MIN_RECOVERY_WRAPPERS_MAINNET=2`).
- `ALLOW_EVM_SIGNATURE_ONLY_RECOVERY=false` — an EVM-only wrapper set is rejected.

Deposit is **blocked** until the vault `backup_status = verified` AND
`recovery_policy_status ∈ {sufficient, strong}`.

## Envelope formats

- Plaintext vault: `version: shade-note-vault-v1`, `vault_id`, timestamps, `notes[]`
  (each with `commitment`, `asset_id`, `amount_7dp`, `note_preimage{owner_secret,
  spend_secret, blinding, nonce, memo_commitment, compliance_tag, source_context}`,
  `deposit_id`, `status`).
- Encrypted envelope: `version: shade-encrypted-vault-v1`, `vault_id`,
  `privy_user_id`, `cipher{AES-256-GCM, iv, tagLength:128}`, `aad{...}`,
  `ciphertext`, `wrappers[]` (each `{id, type, status, kdf, salt, wrapped_key,
  metadata}`).

## Backend rejection (security gate)

The backend refuses to store an envelope (or any payload) containing plaintext
fields: `owner_secret`, `spend_secret`, `blinding`, `nonce`, `note_preimage`,
`vault_master_key`, `raw_signature`, `private_key`, `secret`. Enforced by
`assertNoPlaintextNoteFields` on the envelope and a route-level scan. Logs are
redacted via `redactVaultForLogs`.

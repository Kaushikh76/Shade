# DepositNoteMint Circuit

Status: specified, not yet compiled.

Public inputs:

- `source_domain`
- `cctp_nonce_hash`
- `burn_tx_hash_hash`
- `amount_usdc_7dp`
- `asset_id`
- `recipient_vault`
- `commitment`
- `policy_id`
- `deposit_leaf_index`
- `pool_id`
- `chain_id`

Witness:

- note preimage
- blinding
- nonce
- owner key material

Must prove the note preimage hashes to the public commitment and binds amount, asset, policy, CCTP nonce, source context, pool, and chain.

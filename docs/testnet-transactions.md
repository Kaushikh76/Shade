# Shade Protocol — Testnet Transaction Log

End-to-end testnet run completed **2026-06-30**.  
Networks: **Arbitrum Sepolia** + **Stellar Testnet**  
Git commit: `3bb32d1`

Pool: `CCSC4FB3ZL6TV7FEMRK3QUF5LALTSI5NQFCBH4Q2VMCQMSTQK6HP2XFQ`

---

## 1. CCTP Inbound — Arbitrum Sepolia → Stellar

Burn USDC on Arbitrum, Circle attests, mint and forward to the shielded pool on Stellar.

| Step | Chain | Transaction |
|------|-------|-------------|
| USDC burn | Arbitrum Sepolia | [`0xce52182a6cf9bf8591bccce19c60ba7cd5e3c4c6cb823338756a6d8e6cdab49f`](https://sepolia.arbiscan.io/tx/0xce52182a6cf9bf8591bccce19c60ba7cd5e3c4c6cb823338756a6d8e6cdab49f) |
| mint_and_forward | Stellar Testnet | [`c83dadf4591759ff15139ea5188f1e9460415745707875750231325550b01c87`](https://stellar.expert/explorer/testnet/tx/c83dadf4591759ff15139ea5188f1e9460415745707875750231325550b01c87) |
| receive_cctp_deposit | Stellar Testnet | [`78e6379df98bae91898db0a60e0cfd3383677aea741be373923b2a3e7018c367`](https://stellar.expert/explorer/testnet/tx/78e6379df98bae91898db0a60e0cfd3383677aea741be373923b2a3e7018c367) |

Commitment inserted at leaf 1, root `6091a238c163443761...`

---

## 2. ZK Withdraw — Groth16 proof, k=3 anonymity set

Deposit real note + 2 decoy notes into pool, prove ownership of one without revealing which, withdraw net of relayer fee.

| Step | Chain | Transaction |
|------|-------|-------------|
| CCTP fund pool (burn) | Arbitrum Sepolia | `0xe6246ea1234b...` |
| on-chain withdraw | Stellar Testnet | [`d3b0224a42e5f4407648b566abe4151d372f5dfd4b160480a0b33e554d70b0ed`](https://stellar.expert/explorer/testnet/tx/d3b0224a42e5f4407648b566abe4151d372f5dfd4b160480a0b33e554d70b0ed) |

- Anonymity set: k=3 (1 real note + 2 decoy commitments), pool leaf count 5
- Note value: 5,000,000 (7dp) = 0.50 USDC
- Relayer fee: 100,000 (7dp) = 0.01 USDC
- Net received by user: +4,900,000 (7dp) = 0.49 USDC
- Double-spend attempt: rejected (`WasmVm, InvalidAction` — nullifier already spent)

---

## 3. Private Transfer — hidden-amount shielded transfer

Fund input note via CCTP, prove a transfer to an output note with amount hidden; settle on-chain spending the input nullifier and inserting the output commitment.

| Step | Chain | Transaction |
|------|-------|-------------|
| private_transfer_settle | Stellar Testnet | [`72ec7c9df0cdfa9dcdd06989b0c890ab640a9883285f21d044e9c53935b3a937`](https://stellar.expert/explorer/testnet/tx/72ec7c9df0cdfa9dcdd06989b0c890ab640a9883285f21d044e9c53935b3a937) |

- Public fee: 200,000 (7dp) = 0.02 USDC; input/output amounts NOT in public signals
- Double-spend attempt: rejected (input nullifier spent)

---

## 4. RFQ — Path A: private note → proof-of-fill → Arbitrum USDC payout

User submits encrypted intent; solver checks real Arbitrum inventory, signs a quote, fills on Arbitrum first, then settles on Stellar spending the pool note.

| Step | Chain | Transaction |
|------|-------|-------------|
| CCTP fund pool (burn) | Arbitrum Sepolia | `0xcef7accb53ca...` |
| Arbitrum fill to user | Arbitrum Sepolia | [`0x08347ed9b7347d185294b42733149b4c1ec3e17dc887e9b204c26a2434dc8d39`](https://sepolia.arbiscan.io/tx/0x08347ed9b7347d185294b42733149b4c1ec3e17dc887e9b204c26a2434dc8d39) |
| rfq_settle (nullifier + solver credit) | Stellar Testnet | [`b8f84c20d5877bc7fed19837caf93eff11402f1e85faa38b6d86fc5a7a6b0a2b`](https://stellar.expert/explorer/testnet/tx/b8f84c20d5877bc7fed19837caf93eff11402f1e85faa38b6d86fc5a7a6b0a2b) |

- Note value: 5,000,000 (7dp) = 0.50 USDC
- Fee: 50 bps → solver fill: 497,500 (6dp) = 0.4975 USDC to user on Arbitrum
- Pool balance change: 55,092,200 → 50,092,200 (−5,000,000 7dp credited to solver)
- Negative controls passed: `WrongQuote` (#14) on quote-swap attack, `UnauthorizedSolver` (#23) on rogue key

---

## 5. CCTP Outbound — proof-bound Stellar burn → Arbitrum

User proves note ownership with destination/fee/threshold bound into the Groth16 proof; pool burns USDC via CCTP to the user's Arbitrum address.

| Step | Chain | Transaction |
|------|-------|-------------|
| withdraw_cctp burn | Stellar Testnet | [`380b2c219e85e403dc3c47cd04076f275f39998e915018f697509790216c6de2`](https://stellar.expert/explorer/testnet/tx/380b2c219e85e403dc3c47cd04076f275f39998e915018f697509790216c6de2) |
| Circle attestation | — | `pending_confirmations` at time of run |

- Destination: Arbitrum Sepolia, recipient `0xE488bb2bd58E9C425F525293856FAA529f7b1db3`
- Redirect attack rejected: `WrongDestRecipient` (#18) — proof binds original recipient
- Note nullifier spent within `withdraw_cctp` (double-spend reverts)

---

## Contract addresses (Stellar Testnet)

| Contract | Address |
|----------|---------|
| ShieldedPool | `CCSC4FB3ZL6TV7FEMRK3QUF5LALTSI5NQFCBH4Q2VMCQMSTQK6HP2XFQ` |
| NullifierRegistry | `CBAKCITRZLJZFQC4ISSYH5UESYFUYBFRANVM5VPDA6OH3VDTSLQ2IH67` |
| VerifierWithdraw | `CBMRSDKMUKHH3UBHYMMVST2PY4STQS42WRY5IEQJWFW3HEXCHVPHZLUS` |
| VerifierTransfer | `CAZHGOFBYWHRRE2UWDMDWJKFPK6WZ47LAQXCJ7MVAYRCOYNQ5BHD5SAG` |
| VerifierDepositNoteMint | `CBURZBYMSG4I4SC56LIRS3I3HBKEZCRDTTD2QEO2LUNK3YETTMW4PE7M` |
| CCTP Forwarder | `CA66Q2WFBND6V4UEB7RD4SAXSVIWMD6RA4X3U32ELVFGXV5PJK4T4VSZ` |
| CCTP MessageTransmitter | `CBJ6MTCKKZG73PMDZCJMSFRD7DQEMI4FKDH7CGDSV4W6FHCRBCQAVVJY` |
| USDC SAC | `CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA` |

# Security Notes

- `.env`, `.env.local`, `.env.generated`, proving keys, proof artifacts, and logs are gitignored.
- Setup prints only public addresses and balances.
- Private keys are written to `.env.generated` with mode `0600`.
- API state-changing operations require an idempotency key.
- Postgres schema excludes plaintext note secrets, private keys, raw witnesses, and decrypted RFQ payloads.
- Live commands fail closed when required protocol configuration is absent.

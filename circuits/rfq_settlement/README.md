# RFQSettlement Circuit

Status: **implemented** — embedded in `circuits/withdraw_public/main.circom`.

The `withdraw_public` circuit handles RFQ settlement via `operationType = RFQ_SETTLE` and the following public signals:
- `quoteHash` [10] — `int(sha256(quote)[:31])`; the pool enforces `arg.quote_hash == proof.quoteHash`
- `intentHash` [11] — `int(sha256(intent)[:31])`; the pool enforces `arg.intent_hash == proof.intentHash`
- `fillReceiptHash` [12] — `int(sha256(fill_tx)[:31])`; binds the real on-chain fill transaction

Solver signature verification is handled in the Soroban contract (off-circuit), which matches the design note. The quote hash is bound into the ZK proof, so the solver cannot forge a quote.

No separate `rfq_settlement.circom` is needed.

## P2 #15: signal layout is locked

This is a deliberate reuse, not a placeholder — `circuits/withdraw_public/main.circom`'s
public-signal layout (`[0..9]` core withdraw, `[10..12]` RFQ, `[13..16]` CCTP) is
a **frozen contract** between the circuit, the prover (`packages/proving`), and
`shielded_pool::rfq_settle` / `withdraw_public` / `withdraw_cctp` on-chain — all
four (deposit is separate) read fixed indices out of the same public-signal
array. Do not:
- reorder or insert new signals before index 16 (every existing verifier/caller
  would silently read the wrong index instead of failing loudly);
- add RFQ-specific behavior that isn't also valid for a plain public withdraw
  (they share one circuit and one verifier — there is no way to gate a
  constraint to "only when operationType == RFQ_SETTLEMENT").

If RFQ settlement ever needs a signal withdraw/CCTP don't (e.g. a
solver-specific binding), that is the trigger to split out a dedicated
`rfq_settlement.circom` with its own verifier — not to keep growing this
shared layout further. New RFQ-only signals should be appended (`[17]+`),
never inserted.

# Mainnet Readiness Checklist

P4 #26. The bible's "Mainnet readiness checklist" and "Hackathon
non-negotiables" are prose; this is the trackable version, updated as items
close. **Do not mainnet with real assets until every item below is checked.**
This file is a process gate, not code — nothing here is enforced by a build
or CI step; it exists so "are we ready" has one place to look instead of
being re-litigated from memory each time.

## Hackathon / pre-mainnet non-negotiables (must hold at all times, not just at launch)

- [x] Do not store note secrets server-side — the two server-side
      note-preimage-generation routes were removed (P2 #18); the canonical
      path (`POST /v1/deposits/prepare`) only ever receives a commitment +
      encrypted-payload hash from the client.
- [ ] Do not claim full anonymity — the coordinator reconstructs plaintext
      amounts to match (P2 #16); MPC-as-privacy-guarantee language has been
      corrected in `docs/PENDING.md` / `docs/COMPLETED.md`, but this needs a
      pass over user/marketing-facing copy too (not audited here).
- [ ] Do not claim real fiat payout unless a licensed partner is integrated —
      `anchor_quotes`/`anchor_payouts` proxy an external SEP-38 provider;
      confirm production config points at an actually-licensed partner
      before removing any "simulation" framing.
- [x] Do not use real mainnet funds — testnet-only throughout; no mainnet
      contract IDs or keys present in this repo.
- [ ] Do not bypass CCTP Stellar safety rules — `validateInboundRoute` /
      `LOCKED_CCTP` constants enforce this in code; not independently
      re-audited in this pass.

## Bible mainnet checklist

- [ ] Independent smart contract audit complete.
- [ ] Circuit audit complete.
- [ ] CCTP integration tested with production addresses and small values.
- [x] View-key/compliance process documented and implemented — Shade View
      (P2 #13) ships `POST/GET /v1/reports/view-key` per bible §13.3.
      **Partial**: ASP allow-set compliance now covers deposit/withdraw/CCTP
      (existing) and private_transfer (P2 #14); deny-set non-membership is
      NOT implemented anywhere (see `circuits/compliance_membership/README.md`
      for the scoped follow-up design) — do not check this box as "done" for
      compliance purposes until that lands too.
- [ ] Incident response plan exists.
- [ ] All admin keys in multisig/HSM — `governance_guardian` now supports
      M-of-N guardian quorum + upgrade timelock (P3 #20), but this only binds
      a target contract once that contract's ADMIN is actually transferred to
      the guardian (`shielded_pool::transfer_admin`) — not done automatically,
      and not done for the live testnet pool as of this writing.
- [ ] Proof-of-reserves dashboard live.
- [ ] Emergency pause tested — quorum-gated pause exists (P3 #20) but hasn't
      been drilled against a live deployment.
- [ ] Recovery flows tested — note recovery (`POST /v1/notes/recover`) exists
      for users; committee node liveness/recovery is demonstrated in
      `apps/cli/src/mpc-liveness-e2e.ts` (P4 #24) but that's a 3-process local
      test, not a drill against independently-hosted operators.
- [ ] Legal/regulatory review for payout/remittance corridors complete.

## Independent-operator committee (P4 #24) — code exists, deployment doesn't

The code path for running the MPC committee as genuinely independent
operators exists (`node-server.ts` + `coordinator-server.ts`, verified
end-to-end with a kill/restart test) but nothing has actually deployed it
that way — same three-in-one-process `server.ts` is still what `mpc:dev`
runs, and there's no infra (separate hosts/containers, per-operator secrets
management, mTLS between coordinator and nodes) standing up the split
version yet. Do not count the committee as "independent operators" for a
mainnet decision until it's actually running that way, with each operator
holding only their own key.

## Privacy staging (P4 #25) — see docs/PENDING.md

MPC (bible V3/V4) was built ahead of the TEE matcher (V2) and is live before
the bible's staging says it should be. That's a completed fact, not
something to undo — but it means the remediation in this repo made MPC
*sound* (proof-backed, distinct-signer threshold, no dual-settlement race),
not *private* (the coordinator still sees plaintext amounts). Do not let that
soundness fix read as "MPC is done" — the bible's staging recommendation
(TEE before further MPC investment) still applies to any V3/V4 work like real
secure-comparison matching.

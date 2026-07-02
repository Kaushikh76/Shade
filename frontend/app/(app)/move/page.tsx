"use client"

import { useState } from "react"
import { usePrivy } from "@privy-io/react-auth"
import { useQueryClient } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { useMyNotes, useContracts, balanceUsdc, type NoteRow } from "@/lib/hooks"
import { LiveLog } from "@/components/live-log"
import { ZkPanel, type ZkState } from "@/components/zk-panel"
import { ArrowUpRight, ArrowLeftRight, Check } from "lucide-react"

type Tab = "withdraw" | "swap"

export default function MovePage() {
  const [tab, setTab] = useState<Tab>("withdraw")
  return (
    <div className="mx-auto max-w-2xl space-y-8">
      <div>
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">Move</p>
        <h1 className="mt-2 font-sans text-4xl font-light tracking-tight" style={{ color: "#EDEAE3" }}>Spend your private notes</h1>
      </div>
      <div className="flex gap-2">
        <TabBtn active={tab === "withdraw"} onClick={() => setTab("withdraw")}>Withdraw</TabBtn>
        <TabBtn active={tab === "swap"} onClick={() => setTab("swap")}>Swap (RFQ)</TabBtn>
      </div>
      {tab === "withdraw" ? <Withdraw /> : <Swap />}
    </div>
  )
}

function Withdraw() {
  const { authenticated } = usePrivy()
  const notes = useMyNotes(authenticated)
  const contracts = useContracts()
  const qc = useQueryClient()
  const active = (notes.data?.notes ?? []).filter((n) => n.status === "active")

  const [selected, setSelected] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [jobId, setJobId] = useState<string | undefined>()
  const [zk, setZk] = useState<ZkState>({ circuit: "withdraw_public" })
  const [error, setError] = useState<string | null>(null)
  const [doneTx, setDoneTx] = useState<string | null>(null)

  const commitment = selected ?? active[0]?.commitment ?? null

  async function run() {
    if (!commitment) return
    setBusy(true); setError(null); setJobId(undefined); setDoneTx(null)
    setZk({ circuit: "withdraw_public", verifier: contracts.data?.verifierWithdraw, proving: true, publicSignals: [{ label: "note", value: commitment }] })
    try {
      const res = await api.post<{ job_id: string }>("/v1/withdrawals/assist", { commitment })
      setJobId(res.job_id)
      for (let i = 0; i < 120; i++) {
        await new Promise((r) => setTimeout(r, 2000))
        const job = await api.get<{ status: string; result: Record<string, unknown> | null; error: string | null }>(`/v1/jobs/${res.job_id}`)
        if (job.status === "ready") {
          const tx = String(job.result?.txHash ?? "")
          setDoneTx(tx)
          setZk((z) => ({ ...z, proving: false, verifiedOnChain: true, txHash: tx, nullifier: commitment }))
          await qc.invalidateQueries({ queryKey: ["my-notes"] })
          await qc.invalidateQueries({ queryKey: ["activity"] })
          break
        }
        if (job.status === "failed") throw new Error(job.error ?? "withdraw failed")
      }
    } catch (e) {
      setError((e as { error?: string; message?: string }).error ?? (e as Error).message ?? "withdraw failed")
      setZk((z) => ({ ...z, proving: false }))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-border bg-black/30 p-6">
        <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Private note to spend</p>
        {active.length === 0 ? (
          <p className="mt-3 font-mono text-xs text-muted-foreground">no active notes — <a href="/deposit" className="text-[#2563eb] hover:underline">shield some USDC first</a>.</p>
        ) : (
          <div className="mt-3 space-y-2">
            {active.map((n) => (
              <button
                key={n.commitment}
                onClick={() => setSelected(n.commitment)}
                className={`flex w-full items-center justify-between rounded-lg border px-4 py-3 text-left transition-colors ${
                  commitment === n.commitment ? "border-[#2563eb]/50 bg-[#2563eb]/5" : "border-border hover:border-border/80"
                }`}
              >
                <span className="font-mono text-xs text-foreground/70">{n.commitment.slice(0, 12)}…{n.commitment.slice(-6)}</span>
                <span className="font-sans text-lg font-light" style={{ color: "#EDEAE3" }}>{(Number(n.amount_usdc_7dp) / 1e7).toFixed(2)} <span className="text-xs text-muted-foreground">USDC</span></span>
              </button>
            ))}
          </div>
        )}

        <div className="mt-5 flex items-center gap-2 text-muted-foreground">
          <ArrowUpRight className="h-4 w-4 text-[#2563eb]" />
          <span className="font-mono text-xs">Releases USDC to your Stellar account (backend-assisted signing)</span>
        </div>

        <button
          onClick={run}
          disabled={busy || !commitment}
          className="mt-5 w-full rounded-full border border-[#2563eb]/40 bg-[#2563eb]/10 px-6 py-3 font-mono text-xs uppercase tracking-wider text-foreground transition-colors hover:bg-[#2563eb]/20 disabled:opacity-40"
        >
          {busy ? "Proving + releasing…" : "Withdraw note"}
        </button>
        {error && <p className="mt-3 font-mono text-xs text-red-400">error: {error}</p>}
        {doneTx && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-emerald-400/25 bg-emerald-400/5 px-4 py-2.5 font-mono text-xs text-emerald-400">
            <Check className="h-3.5 w-3.5" /> Withdrawn · nullifier spent · USDC released
          </div>
        )}
      </div>

      {jobId && <LiveLog jobId={jobId} title="Prover + Stellar · withdraw_public ZK" />}
      {(jobId || busy) && <ZkPanel state={zk} />}
    </div>
  )
}

// The Swap page has two modes for turning a private USDC note into XLM:
//  - Solver (RFQ): a solver quotes + signs, pool settles atomically (rfq_settle_atomic_swap).
//    The amount is visible to the solver. Cross-asset payout to your Stellar account.
//  - Private Match (MPC): a threshold committee crosses your note against a counterparty
//    note note<->note (mpc_settle_priced). The amount is revealed to no single party.
type Mode = "solver" | "match"

const MODES: Record<Mode, {
  label: string; endpoint: string; circuit: string; price: number; priceUnit: string
  desc: string; cta: string; ctaBusy: string; success: (xlm: string) => string
  logTitle: string; outField: string; nullSignals: string
}> = {
  solver: {
    label: "Solver (RFQ)", endpoint: "/v1/rfq/assist", circuit: "rfq_atomic_swap",
    price: 2.0, priceUnit: "XLM/USDC",
    desc: "Solver-quoted, signed (ed25519), and settled atomically on-chain (rfq_settle_atomic_swap). One transaction: XLM to you, USDC to the solver.",
    cta: "Swap note for XLM", ctaBusy: "Proving + settling…",
    success: (xlm) => `Swapped · nullifier spent · ${xlm} XLM delivered`,
    logTitle: "Prover + Solver + Stellar · atomic USDC→XLM swap", outField: "quotedOutputXlm", nullSignals: "1",
  },
  match: {
    label: "Private Match (MPC)", endpoint: "/v1/mpc/assist", circuit: "mpc_priced_settlement",
    price: 1.0, priceUnit: "XLM/USDC",
    desc: "Crossed against a counterparty note by a 3-node MPC committee (threshold ed25519), settled note↔note on-chain (mpc_settle_priced). The amount is revealed to no single party.",
    cta: "Match privately for XLM", ctaBusy: "Proving + crossing…",
    success: (xlm) => `Matched · 2 nullifiers spent · ${xlm} XLM note received`,
    logTitle: "Prover + Committee + Stellar · private USDC↔XLM match", outField: "outputXlm", nullSignals: "2",
  },
}

function Swap() {
  const { authenticated } = usePrivy()
  const notes = useMyNotes(authenticated)
  const contracts = useContracts()
  const qc = useQueryClient()
  const active = (notes.data?.notes ?? []).filter((n) => n.status === "active")

  const [mode, setMode] = useState<Mode>("solver")
  const [selected, setSelected] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [jobId, setJobId] = useState<string | undefined>()
  const [zk, setZk] = useState<ZkState>({ circuit: MODES.solver.circuit })
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<{ tx: string; xlm: string } | null>(null)

  const cfg = MODES[mode]
  const commitment = selected ?? active[0]?.commitment ?? null
  const note = active.find((n) => n.commitment === commitment) ?? active[0]
  const inUsdc = note ? Number(note.amount_usdc_7dp) / 1e7 : 0
  const outXlm = inUsdc * cfg.price

  function pickMode(m: Mode) {
    if (busy) return
    setMode(m); setError(null); setDone(null); setJobId(undefined)
    setZk({ circuit: MODES[m].circuit })
  }

  async function run() {
    if (!commitment) return
    setBusy(true); setError(null); setJobId(undefined); setDone(null)
    const signals = [{ label: "note", value: commitment }, { label: "output", value: "XLM" }]
    if (mode === "match") signals.push({ label: "committee", value: "3-of-3 threshold" })
    setZk({ circuit: cfg.circuit, verifier: contracts.data?.verifierWithdraw, proving: true, publicSignals: signals })
    try {
      const res = await api.post<{ job_id: string }>(cfg.endpoint, { commitment })
      setJobId(res.job_id)
      for (let i = 0; i < 120; i++) {
        await new Promise((r) => setTimeout(r, 2000))
        const job = await api.get<{ status: string; result: Record<string, unknown> | null; error: string | null }>(`/v1/jobs/${res.job_id}`)
        if (job.status === "ready") {
          const tx = String(job.result?.txHash ?? "")
          const xlm = String(job.result?.[cfg.outField] ?? outXlm.toFixed(4))
          setDone({ tx, xlm })
          setZk((z) => ({ ...z, proving: false, verifiedOnChain: true, txHash: tx, nullifier: String(job.result?.nullifierA ?? commitment) }))
          await qc.invalidateQueries({ queryKey: ["my-notes"] })
          await qc.invalidateQueries({ queryKey: ["activity"] })
          break
        }
        if (job.status === "failed") throw new Error(job.error ?? "swap failed")
      }
    } catch (e) {
      setError((e as { error?: string; message?: string }).error ?? (e as Error).message ?? "swap failed")
      setZk((z) => ({ ...z, proving: false }))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Mode toggle: Solver (RFQ) vs Private Match (MPC) */}
      <div className="grid grid-cols-2 gap-2 rounded-xl border border-border bg-black/20 p-1.5">
        {(Object.keys(MODES) as Mode[]).map((m) => (
          <button
            key={m}
            onClick={() => pickMode(m)}
            className={`rounded-lg px-4 py-2.5 font-mono text-xs uppercase tracking-wider transition-colors ${
              mode === m ? "bg-[#2563eb]/15 text-foreground" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {MODES[m].label}
          </button>
        ))}
      </div>

      <div className="rounded-xl border border-border bg-black/30 p-6">
        <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Private note to convert</p>
        {active.length === 0 ? (
          <p className="mt-3 font-mono text-xs text-muted-foreground">no active notes — <a href="/deposit" className="text-[#2563eb] hover:underline">shield some USDC first</a>.</p>
        ) : (
          <div className="mt-3 space-y-2">
            {active.map((n) => (
              <button
                key={n.commitment}
                onClick={() => setSelected(n.commitment)}
                className={`flex w-full items-center justify-between rounded-lg border px-4 py-3 text-left transition-colors ${
                  commitment === n.commitment ? "border-[#2563eb]/50 bg-[#2563eb]/5" : "border-border hover:border-border/80"
                }`}
              >
                <span className="font-mono text-xs text-foreground/70">{n.commitment.slice(0, 12)}…{n.commitment.slice(-6)}</span>
                <span className="font-sans text-lg font-light" style={{ color: "#EDEAE3" }}>{(Number(n.amount_usdc_7dp) / 1e7).toFixed(2)} <span className="text-xs text-muted-foreground">USDC</span></span>
              </button>
            ))}
          </div>
        )}

        {/* Preview: USDC in -> XLM out */}
        <div className="mt-5 flex items-center justify-between gap-4 rounded-lg border border-border bg-black/40 px-4 py-4">
          <div className="text-center">
            <p className="font-sans text-2xl font-light" style={{ color: "#EDEAE3" }}>{inUsdc.toFixed(2)}</p>
            <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">USDC · private</p>
          </div>
          <ArrowLeftRight className="h-5 w-5 shrink-0 text-[#2563eb]" />
          <div className="text-center">
            <p className="font-sans text-2xl font-light" style={{ color: "#EDEAE3" }}>{outXlm.toFixed(2)}</p>
            <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">XLM · {mode === "match" ? "matched" : "to you"}</p>
          </div>
        </div>
        <p className="mt-3 flex items-start gap-2 font-mono text-xs leading-relaxed text-muted-foreground">
          <ArrowUpRight className="mt-0.5 h-4 w-4 shrink-0 text-[#2563eb]" />
          <span>{cfg.price.toFixed(1)} {cfg.priceUnit} · {cfg.desc}</span>
        </p>

        <button
          onClick={run}
          disabled={busy || !commitment}
          className="mt-5 w-full rounded-full border border-[#2563eb]/40 bg-[#2563eb]/10 px-6 py-3 font-mono text-xs uppercase tracking-wider text-foreground transition-colors hover:bg-[#2563eb]/20 disabled:opacity-40"
        >
          {busy ? cfg.ctaBusy : cfg.cta}
        </button>
        {error && <p className="mt-3 font-mono text-xs text-red-400">error: {error}</p>}
        {done && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-emerald-400/25 bg-emerald-400/5 px-4 py-2.5 font-mono text-xs text-emerald-400">
            <Check className="h-3.5 w-3.5" /> {cfg.success(done.xlm)}
          </div>
        )}
      </div>

      {jobId && <LiveLog jobId={jobId} title={cfg.logTitle} />}
      {(jobId || busy) && <ZkPanel state={zk} />}
    </div>
  )
}

function TabBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-5 py-2 font-mono text-xs uppercase tracking-wider transition-colors ${
        active ? "border-[#2563eb]/50 bg-[#2563eb]/10 text-foreground" : "border-border text-muted-foreground hover:text-foreground"
      }`}
    >
      {children}
    </button>
  )
}

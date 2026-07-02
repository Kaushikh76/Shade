"use client"

import { useEffect, useRef, useState } from "react"
import { usePrivy } from "@privy-io/react-auth"
import { useMe, useSyncWallets, useContracts, useActivity, useMyNotes, balanceUsdc } from "@/lib/hooks"
import { useNoteVaults, isDepositReady } from "@/lib/vault-hooks"
import { walletsFromPrivyUser } from "@/lib/privy-wallets"
import { VaultSetup } from "@/components/vault-setup"
import { TxLink } from "@/components/tx-link"
import { Copy, ExternalLink, ShieldCheck, ShieldAlert, Zap, Users, ArrowDownLeft, ArrowUpRight, ArrowLeftRight } from "lucide-react"

// Fixed demo denominations: a note is 0.5 USDC; solver swaps price 2.0 XLM/USDC
// (=> 1.0 XLM each), committee matches cross 1:1 (=> 0.5 XLM each).
const SWAP_XLM_EACH = 1.0
const MATCH_XLM_EACH = 0.5

export default function DashboardPage() {
  const { user, authenticated } = usePrivy()
  const me = useMe(authenticated)
  const contracts = useContracts()
  const activity = useActivity(authenticated)
  const notes = useMyNotes(authenticated)
  const balance = balanceUsdc(notes.data?.notes)
  const sync = useSyncWallets()
  const synced = useRef(false)
  const vaults = useNoteVaults(authenticated)
  const readyVault = (vaults.data?.vaults ?? []).find(isDepositReady)
  const hasVault = (vaults.data?.vaults ?? []).length > 0
  const [showSetup, setShowSetup] = useState(false)

  // On first authenticated mount, push Privy linked wallets to the backend, then refresh /v1/me.
  useEffect(() => {
    if (!authenticated || synced.current) return
    const wallets = walletsFromPrivyUser(user as never)
    if (wallets.length === 0) return
    synced.current = true
    sync.mutate(wallets, { onSuccess: () => me.refetch() })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authenticated, user])

  const wallets = me.data?.wallets ?? []

  // XLM received via the two Move flows, derived from settled activity events.
  const acts = activity.data?.activity ?? []
  const swapEvents = acts.filter((a) => a.event_type === "rfq.swap.settled")
  const matchEvents = acts.filter((a) => a.event_type === "mpc.match.settled")
  const swapXlm = swapEvents.length * SWAP_XLM_EACH
  const matchXlm = matchEvents.length * MATCH_XLM_EACH
  const receivedXlm = swapXlm + matchXlm
  const lastSwapTx = swapEvents.find((a) => a.tx_hash)?.tx_hash ?? null
  const lastMatchTx = matchEvents.find((a) => a.tx_hash)?.tx_hash ?? null

  return (
    <div className="space-y-10">
      <div>
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">Private balance</p>
        <h1 className="mt-2 font-sans text-6xl font-light tracking-tight" style={{ color: "#EDEAE3" }}>
          {balance.toFixed(2)} <span className="text-2xl text-muted-foreground">USDC</span>
        </h1>
        <p className="mt-2 font-mono text-xs text-muted-foreground">shielded on Stellar · hidden from public chain</p>
      </div>

      {/* Received (XLM) — the value out of swaps + private matches */}
      <div className="rounded-xl border border-border bg-black/30 p-6 backdrop-blur-sm">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              <ArrowDownLeft className="h-3.5 w-3.5 text-emerald-400" /> Received · XLM
            </p>
            <p className="mt-2 font-sans text-4xl font-light tracking-tight text-emerald-400">
              {receivedXlm.toFixed(2)} <span className="text-lg text-muted-foreground">XLM</span>
            </p>
          </div>
          <p className="max-w-[13rem] text-right font-mono text-[10px] leading-relaxed text-muted-foreground">
            cross-asset output from your USDC notes · settled on-chain
          </p>
        </div>

        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          <ReceivedRow
            icon={<Zap className="h-4 w-4 text-[#2563eb]" />}
            title="Solver swaps"
            count={swapEvents.length}
            xlm={swapXlm}
            note="RFQ · 2.0 XLM/USDC"
            tx={lastSwapTx}
          />
          <ReceivedRow
            icon={<Users className="h-4 w-4 text-[#2563eb]" />}
            title="Private matches"
            count={matchEvents.length}
            xlm={matchXlm}
            note="MPC committee · 1:1"
            tx={lastMatchTx}
          />
        </div>
        {receivedXlm === 0 && (
          <p className="mt-4 font-mono text-[10px] text-muted-foreground">
            no swaps or matches yet — <a href="/move" className="text-[#2563eb] hover:underline">convert a note in Move</a>.
          </p>
        )}
      </div>

      {/* Vault status / gate */}
      {!vaults.isLoading && (
        readyVault ? (
          <div className="flex items-center justify-between gap-4 rounded-lg border border-emerald-400/25 bg-emerald-400/5 px-5 py-3">
            <span className="flex items-center gap-2 font-mono text-xs text-emerald-400">
              <ShieldCheck className="h-4 w-4" /> Vault ready · backup verified · you can deposit
            </span>
            <a href="/deposit" className="font-mono text-xs uppercase tracking-wider text-foreground hover:underline">Deposit →</a>
          </div>
        ) : (
          <div className="flex items-center justify-between gap-4 rounded-lg border border-[#2563eb]/30 bg-[#2563eb]/5 px-5 py-3">
            <span className="flex items-center gap-2 font-mono text-xs text-[#2563eb]">
              <ShieldAlert className="h-4 w-4" /> {hasVault ? "Finish vault backup to deposit" : "Set up your private vault before depositing"}
            </span>
            <button onClick={() => setShowSetup(true)} className="rounded-full border border-[#2563eb]/40 bg-[#2563eb]/10 px-4 py-1.5 font-mono text-[10px] uppercase tracking-wider text-foreground hover:bg-[#2563eb]/20">
              Set up vault
            </button>
          </div>
        )
      )}

      <div className="grid gap-6 md:grid-cols-2">
        {/* Account */}
        <Card title="Account">
          <Field label="Identity (Privy DID)" value={me.data?.privy_user_id ?? user?.id ?? "—"} mono />
          {me.data?.email && <Field label="Email" value={me.data.email} />}
          <div className="mt-3">
            <p className="mb-2 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Linked wallets</p>
            {wallets.length === 0 && <p className="font-mono text-xs text-muted-foreground">syncing…</p>}
            {wallets.map((w) => (
              <div key={w.id} className="flex items-center justify-between gap-3 py-1">
                <span className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] uppercase text-muted-foreground">
                  {w.wallet_type}
                </span>
                <Mono value={w.address} />
              </div>
            ))}
          </div>
        </Card>

        {/* Network / contracts */}
        <Card title="Network">
          <Field label="Chain" value="Stellar testnet + Arbitrum Sepolia" />
          <Field label="Shielded pool" value={contracts.data?.shadePool ?? "—"} mono explorer="contract" />
          <Field label="Withdraw verifier" value={contracts.data?.verifierWithdraw ?? "—"} mono explorer="contract" />
          <Field label="USDC (SAC)" value={contracts.data?.usdcSac ?? "—"} mono explorer="contract" />
        </Card>
      </div>

      {/* Activity */}
      <Card title="Recent activity">
        {(() => {
          const items = (activity.data?.activity ?? []).filter((a) => !ACTIVITY_HIDE.test(a.event_type)).slice(0, 8)
          if (items.length === 0) return <p className="font-mono text-xs text-muted-foreground">no activity yet — shield some USDC to begin.</p>
          return (
            <div className="space-y-0.5">
              {items.map((a, i) => <ActivityItem key={i} event={a.event_type} tx={a.tx_hash} at={a.created_at} />)}
            </div>
          )
        })()}
      </Card>

      {/* Vault setup modal */}
      {showSetup && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6 backdrop-blur-sm" onClick={() => setShowSetup(false)}>
          <div className="w-full max-w-2xl rounded-xl border border-border bg-[#0a0a0c] p-8" onClick={(e) => e.stopPropagation()}>
            <VaultSetup
              onDone={() => {
                setShowSetup(false)
                vaults.refetch()
              }}
            />
            <button onClick={() => setShowSetup(false)} className="mt-6 font-mono text-xs text-muted-foreground hover:text-foreground">
              close
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// Noise + intermediate events we don't surface in the feed (wallet syncs, "prepare" steps).
const ACTIVITY_HIDE = /^wallet\.|\.prepare$/

type Tone = "in" | "out" | "swap" | "vault" | "info"
const EVENT_META: Record<string, { label: string; sub?: string; tone: Tone }> = {
  "deposit.burn_submitted": { label: "Shielded USDC", sub: "0.50 USDC → private note", tone: "in" },
  "withdraw.settled": { label: "Withdrew USDC", sub: "0.50 USDC → Stellar account", tone: "out" },
  "rfq.swap.settled": { label: "Swapped to XLM", sub: "0.50 USDC → 1.00 XLM · solver", tone: "swap" },
  "mpc.match.settled": { label: "Privately matched", sub: "0.50 USDC ↔ 0.50 XLM · committee", tone: "swap" },
  "vault.create": { label: "Vault created", tone: "vault" },
  "vault.backup_verified": { label: "Vault backup verified", tone: "vault" },
}
const TONE_ICON: Record<Tone, React.ReactNode> = {
  in: <ArrowDownLeft className="h-3.5 w-3.5 text-emerald-400" />,
  out: <ArrowUpRight className="h-3.5 w-3.5 text-amber-400" />,
  swap: <ArrowLeftRight className="h-3.5 w-3.5 text-[#2563eb]" />,
  vault: <ShieldCheck className="h-3.5 w-3.5 text-[#2563eb]" />,
  info: <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/50" />,
}
function humanize(ev: string): string {
  return ev.replace(/[._]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
}

function ActivityItem({ event, tx, at }: { event: string; tx: string | null; at: string }) {
  const meta = EVENT_META[event] ?? { label: humanize(event), tone: "info" as Tone }
  return (
    <div className="flex items-center justify-between gap-4 border-b border-border/40 py-2 last:border-0">
      <div className="flex min-w-0 items-center gap-3">
        <span className="flex h-6 w-6 shrink-0 items-center justify-center">{TONE_ICON[meta.tone]}</span>
        <div className="min-w-0">
          <p className="truncate font-mono text-xs text-foreground/90">{meta.label}</p>
          {meta.sub && <p className="truncate font-mono text-[10px] text-muted-foreground">{meta.sub}</p>}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-4">
        {tx && <TxLink hash={tx} />}
        <span className="font-mono text-[10px] text-muted-foreground">{new Date(at).toLocaleTimeString()}</span>
      </div>
    </div>
  )
}

function ReceivedRow({ icon, title, count, xlm, note, tx }: { icon: React.ReactNode; title: string; count: number; xlm: number; note: string; tx: string | null }) {
  return (
    <div className="rounded-lg border border-border bg-black/40 p-4">
      <div className="flex items-center justify-between gap-3">
        <span className="flex items-center gap-2 font-mono text-xs text-foreground/80">{icon}{title}</span>
        <span className="font-sans text-lg font-light text-emerald-400">+{xlm.toFixed(2)} <span className="text-xs text-muted-foreground">XLM</span></span>
      </div>
      <div className="mt-2 flex items-center justify-between gap-3 font-mono text-[10px] text-muted-foreground">
        <span>{count} {count === 1 ? "conversion" : "conversions"} · {note}</span>
        {tx && <TxLink hash={tx} label="latest" />}
      </div>
    </div>
  )
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-black/30 p-5 backdrop-blur-sm">
      <p className="mb-4 font-mono text-xs uppercase tracking-wider text-muted-foreground">{title}</p>
      {children}
    </div>
  )
}

function Field({ label, value, mono, explorer }: { label: string; value: string; mono?: boolean; explorer?: "contract" }) {
  return (
    <div className="flex items-center justify-between gap-4 py-1">
      <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
      {mono ? <Mono value={value} explorer={explorer} /> : <span className="text-sm text-foreground/90">{value}</span>}
    </div>
  )
}

function Mono({ value, explorer }: { value: string; explorer?: "contract" }) {
  const [copied, setCopied] = useState(false)
  const short = value && value.length > 16 ? `${value.slice(0, 6)}…${value.slice(-6)}` : value
  const url = explorer === "contract" ? `https://stellar.expert/explorer/testnet/contract/${value}` : undefined
  return (
    <span className="flex items-center gap-1.5 font-mono text-xs text-foreground/80">
      {short}
      {value && value !== "—" && (
        <>
          <button
            onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1000) }}
            className="text-muted-foreground hover:text-foreground"
            title="copy"
          >
            <Copy className="h-3 w-3" />
          </button>
          {url && (
            <a href={url} target="_blank" rel="noreferrer" className="text-muted-foreground hover:text-foreground">
              <ExternalLink className="h-3 w-3" />
            </a>
          )}
          {copied && <span className="text-[10px] text-emerald-400">copied</span>}
        </>
      )}
    </span>
  )
}

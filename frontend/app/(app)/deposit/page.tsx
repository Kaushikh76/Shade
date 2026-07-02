"use client"

import { useState } from "react"
import { usePrivy, useWallets } from "@privy-io/react-auth"
import { useQueryClient } from "@tanstack/react-query"
import { createWalletClient, createPublicClient, custom, http, parseAbi } from "viem"
import { arbitrumSepolia } from "viem/chains"
import { api, newIdempotencyKey } from "@/lib/api"
import { useNoteVaults, isDepositReady } from "@/lib/vault-hooks"
import { LiveLog } from "@/components/live-log"
import { ZkPanel, type ZkState } from "@/components/zk-panel"
import { TxLink } from "@/components/tx-link"
import { useContracts } from "@/lib/hooks"
import { ArrowDown, Check, Loader2 } from "lucide-react"

// The note denomination is a fixed 0.5 USDC. We burn slightly more (0.505) to cover
// the CCTP fast-transfer fee so the minted amount fully backs the note.
const NOTE_USDC = 0.5
const BURN_6DP = "505000"
const POLICY = "shade:default-testnet-policy:v1"
const ARB_RPC = "https://sepolia-rollup.arbitrum.io/rpc"

type Step = { label: string; status: "idle" | "running" | "done" | "error"; detail?: string; tx?: string; chain?: "stellar" | "arb" }
const coerce = (a: unknown) => (typeof a === "string" && /^\d+$/.test(a) ? BigInt(a) : a)

async function sha256Hex(s: string): Promise<string> {
  const buf = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("")
}

export default function DepositPage() {
  const { user, authenticated } = usePrivy()
  const { wallets } = useWallets()
  const contracts = useContracts()
  const qc = useQueryClient()
  const vaults = useNoteVaults(authenticated)
  const readyVault = (vaults.data?.vaults ?? []).find(isDepositReady)

  const [busy, setBusy] = useState(false)
  const [steps, setSteps] = useState<Step[]>([])
  const [jobId, setJobId] = useState<string | undefined>()
  const [zk, setZk] = useState<ZkState>({ circuit: "deposit_note_mint" })
  const [error, setError] = useState<string | null>(null)

  const evmWallet = wallets.find((w) => w.address?.startsWith("0x"))
  const setStep = (i: number, p: Partial<Step>) => setSteps((prev) => prev.map((s, idx) => (idx === i ? { ...s, ...p } : s)))

  async function run() {
    if (!readyVault || !user?.id || !evmWallet) return
    setBusy(true); setError(null); setJobId(undefined)
    setZk({ circuit: "deposit_note_mint", verifier: contracts.data?.verifierDepositNoteMint })
    const init: Step[] = [
      { label: "Generate private note (server-assisted coinutils)", status: "idle" },
      { label: "Prepare CCTP burn", status: "idle" },
      { label: "Approve USDC (MetaMask)", status: "idle" },
      { label: "Burn on Arbitrum (MetaMask)", status: "idle" },
      { label: "Shield on Stellar + ZK proof (backend)", status: "idle" },
    ]
    setSteps(init)
    try {
      // 1) server generates the circuit-valid coin + commitment.
      setStep(0, { status: "running" })
      const coin = await api.post<{ commitment: string; amount_7dp: string; new_root: string }>("/v1/notes/coin")
      setStep(0, { status: "done", detail: `${coin.commitment.slice(0, 10)}…` })
      setZk((z) => ({ ...z, publicSignals: [{ label: "commitment", value: coin.commitment }] }))

      // 2) prepare the deposit (returns approve + burn tx requests for MetaMask).
      setStep(1, { status: "running" })
      const policyHex = "0x" + (await sha256Hex(POLICY)).slice(0, 64)
      const prep = await api.post<{
        deposit_id: string
        approval_tx_request: { to: `0x${string}`; abi: string; args: unknown[] }
        burn_tx_request: { to: `0x${string}`; abi: string; args: unknown[] }
      }>(
        "/v1/deposits/prepare",
        {
          amount_usdc_6dp: BURN_6DP,
          source_chain: "arbitrum-sepolia",
          source_wallet_address: evmWallet.address,
          vault_id: readyVault.vault_id,
          commitment: coin.commitment,
          encrypted_note_payload_hash: coin.commitment,
          policy_id: policyHex,
        },
        newIdempotencyKey(),
      )
      setStep(1, { status: "done", detail: prep.deposit_id.slice(0, 12) })

      // 3+4) sign on MetaMask (Arbitrum Sepolia).
      await evmWallet.switchChain(arbitrumSepolia.id)
      const provider = await evmWallet.getEthereumProvider()
      const account = evmWallet.address as `0x${string}`
      const walletClient = createWalletClient({ account, chain: arbitrumSepolia, transport: custom(provider) })
      const pub = createPublicClient({ chain: arbitrumSepolia, transport: http(ARB_RPC) })
      // Arbitrum Sepolia base fee drifts; estimate fresh and add a 2x buffer so the
      // tx isn't rejected for maxFeePerGas < baseFee.
      const fee = await pub.estimateFeesPerGas()
      const gas = { maxFeePerGas: fee.maxFeePerGas * 2n, maxPriorityFeePerGas: fee.maxPriorityFeePerGas }

      setStep(2, { status: "running", detail: "confirm in MetaMask" })
      const approveHash = await walletClient.writeContract({
        address: prep.approval_tx_request.to,
        abi: parseAbi([prep.approval_tx_request.abi]),
        functionName: "approve",
        args: prep.approval_tx_request.args.map(coerce) as never,
        ...gas,
      })
      await pub.waitForTransactionReceipt({ hash: approveHash })
      setStep(2, { status: "done", tx: approveHash, chain: "arb" })

      setStep(3, { status: "running", detail: "confirm in MetaMask" })
      const burnHash = await walletClient.writeContract({
        address: prep.burn_tx_request.to,
        abi: parseAbi([prep.burn_tx_request.abi]),
        functionName: "depositForBurnWithHook",
        args: prep.burn_tx_request.args.map(coerce) as never,
        ...gas,
      })
      await pub.waitForTransactionReceipt({ hash: burnHash })
      setStep(3, { status: "done", tx: burnHash, chain: "arb" })

      // 5) hand the burn to the relayer; it validates, mints on Stellar, generates
      // the deposit ZK proof, and registers the note on-chain.
      setStep(4, { status: "running" })
      const submit = await api.post<{ job_id: string }>(`/v1/deposits/${prep.deposit_id}/burn-submitted`, {
        burn_tx_hash: burnHash,
        source_chain: "arbitrum-sepolia",
        source_wallet_address: evmWallet.address,
      })
      setJobId(submit.job_id)

      // poll the relayer job to completion.
      for (let i = 0; i < 240; i++) {
        await new Promise((r) => setTimeout(r, 2000))
        const job = await api.get<{ status: string; result: Record<string, unknown> | null; error: string | null }>(`/v1/jobs/${submit.job_id}`)
        if (job.status === "ready") {
          const tx = String(job.result?.receiveDepositTxHash ?? "")
          setStep(4, { status: "done", detail: `note active · leaf ${job.result?.leafIndex}` })
          setZk((z) => ({ ...z, verifiedOnChain: true, txHash: tx }))
          await qc.invalidateQueries({ queryKey: ["my-notes"] })
          await qc.invalidateQueries({ queryKey: ["activity"] })
          break
        }
        if (job.status === "failed") { throw new Error(job.error ?? "relayer job failed") }
      }
    } catch (e) {
      const msg = (e as { error?: string; message?: string }).error ?? (e as Error).message ?? "deposit failed"
      setError(msg)
      setSteps((prev) => prev.map((s) => (s.status === "running" ? { ...s, status: "error" } : s)))
    } finally {
      setBusy(false)
    }
  }

  if (!vaults.isLoading && !readyVault) {
    return (
      <div className="flex min-h-[50vh] flex-col items-center justify-center gap-4 text-center">
        <p className="font-sans text-2xl font-light" style={{ color: "#EDEAE3" }}>Set up your vault first</p>
        <p className="max-w-md font-mono text-xs text-muted-foreground">You need a verified private vault before you can shield funds.</p>
        <a href="/dashboard" className="rounded-full border border-[#2563eb]/40 bg-[#2563eb]/10 px-5 py-2 font-mono text-xs uppercase tracking-wider text-foreground hover:bg-[#2563eb]/20">Go to dashboard</a>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-2xl space-y-8">
      <div>
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-muted-foreground">Shield</p>
        <h1 className="mt-2 font-sans text-4xl font-light tracking-tight" style={{ color: "#EDEAE3" }}>Deposit USDC privately</h1>
        <p className="mt-2 font-mono text-xs text-muted-foreground">Arbitrum → Stellar via CCTP. Your USDC becomes a private note, hidden from the public chain.</p>
      </div>

      {/* Amount card */}
      <div className="rounded-xl border border-border bg-black/30 p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">From · Arbitrum Sepolia</p>
            <p className="mt-1 font-mono text-xs text-foreground/70">{evmWallet ? `${evmWallet.address.slice(0, 6)}…${evmWallet.address.slice(-4)}` : "connect wallet"}</p>
          </div>
          <p className="font-sans text-3xl font-light" style={{ color: "#EDEAE3" }}>{NOTE_USDC.toFixed(2)} <span className="text-lg text-muted-foreground">USDC</span></p>
        </div>
        <div className="my-4 flex justify-center"><ArrowDown className="h-5 w-5 text-[#2563eb]" /></div>
        <div className="flex items-center justify-between">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">To · private note on Stellar</p>
            <p className="mt-1 font-mono text-xs text-emerald-400/80">shielded · nullifier-protected</p>
          </div>
          <p className="font-sans text-3xl font-light text-emerald-400">{NOTE_USDC.toFixed(2)} <span className="text-lg text-muted-foreground">USDC</span></p>
        </div>
        <button
          onClick={run}
          disabled={busy || !evmWallet}
          className="mt-6 w-full rounded-full border border-[#2563eb]/40 bg-[#2563eb]/10 px-6 py-3 font-mono text-xs uppercase tracking-wider text-foreground transition-colors hover:bg-[#2563eb]/20 disabled:opacity-40"
        >
          {busy ? "Shielding…" : `Shield ${NOTE_USDC.toFixed(2)} USDC`}
        </button>
        <p className="mt-2 text-center font-mono text-[10px] text-muted-foreground">burns ~0.505 USDC incl. CCTP bridge fee · fixed 0.5 note denomination</p>
      </div>

      {/* Steps */}
      {steps.length > 0 && (
        <div className="space-y-2 rounded-lg border border-border bg-black/40 p-4">
          {steps.map((s, i) => (
            <div key={i} className="flex items-center gap-3 font-mono text-xs">
              {s.status === "running" ? <Loader2 className="h-3.5 w-3.5 animate-spin text-[#2563eb]" />
                : s.status === "done" ? <Check className="h-3.5 w-3.5 text-emerald-400" />
                : s.status === "error" ? <span className="h-3.5 w-3.5 text-center text-red-400">x</span>
                : <span className="h-3.5 w-3.5 rounded-full border border-muted-foreground/40" />}
              <span className={s.status === "done" ? "text-foreground/80" : "text-muted-foreground"}>{s.label}</span>
              {s.detail && <span className="text-emerald-400/80">· {s.detail}</span>}
              {s.tx && <span className="text-muted-foreground">· <TxLink hash={s.tx} chain={s.chain} /></span>}
            </div>
          ))}
          {error && <p className="pt-2 font-mono text-xs text-red-400">error: {error}</p>}
        </div>
      )}

      {/* Live log + ZK panel */}
      {jobId && <LiveLog jobId={jobId} title="Backend · CCTP + ZK note registration" />}
      {steps.length > 0 && <ZkPanel state={zk} />}
    </div>
  )
}

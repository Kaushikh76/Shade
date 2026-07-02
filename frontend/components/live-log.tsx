"use client"

// Terminal-style live log for an async backend job. Polls GET /v1/jobs/:id and
// streams its event timeline. Used on every action page (deposit/withdraw/rfq/exit).
import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { TxLink } from "@/components/tx-link"

// Human labels for the tx-hash fields a relayer job result may carry.
const TX_LABELS: Record<string, string> = {
  txHash: "settle tx",
  receiveDepositTxHash: "shield tx",
  mintForwardTxHash: "mint tx",
  burnTxHash: "burn tx",
  fillTxHash: "fill tx",
  mintTxHash: "mint tx",
}
function txFields(result: Record<string, unknown> | null): { label: string; hash: string }[] {
  if (!result) return []
  const out: { label: string; hash: string }[] = []
  for (const [k, v] of Object.entries(result)) {
    if (typeof v !== "string" || !/Hash$/.test(k)) continue
    if (/^0x[a-fA-F0-9]{64}$/.test(v) || /^[A-Fa-f0-9]{64}$/.test(v)) out.push({ label: TX_LABELS[k] ?? k, hash: v })
  }
  return out
}

type JobEvent = { status: string; detail: string | null; created_at: string }
type Job = {
  job_id: string
  type: string
  status: string
  attempts: number
  result: Record<string, unknown> | null
  error: string | null
  events: JobEvent[]
}

const TERMINAL = new Set(["ready", "failed"])

export function LiveLog({ jobId, title = "Live log" }: { jobId?: string; title?: string }) {
  const { data } = useQuery({
    queryKey: ["job", jobId],
    queryFn: () => api.get<Job>(`/v1/jobs/${jobId}`),
    enabled: !!jobId,
    refetchInterval: (q) => {
      const s = (q.state.data as Job | undefined)?.status
      return s && TERMINAL.has(s) ? false : 1500
    },
  })

  return (
    <div className="rounded-lg border border-border bg-black/40 backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-border px-4 py-2">
        <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">{title}</span>
        {data && <StatusChip status={data.status} />}
      </div>
      <div className="max-h-64 overflow-y-auto p-4 font-mono text-xs leading-relaxed">
        {!jobId && <p className="text-muted-foreground">waiting for job…</p>}
        {jobId && !data && <p className="text-muted-foreground">connecting…</p>}
        {data?.events?.map((e, i) => (
          <div key={i} className="flex gap-3 py-0.5">
            <span className="shrink-0 text-muted-foreground">{new Date(e.created_at).toLocaleTimeString()}</span>
            <span className="shrink-0 text-[#2563eb]">{e.status}</span>
            <span className="text-foreground/80">{e.detail}</span>
          </div>
        ))}
        {data?.error && <div className="py-0.5 text-red-400">error: {data.error}</div>}
      </div>
      {txFields(data?.result ?? null).length > 0 && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border px-4 py-2.5">
          {txFields(data?.result ?? null).map((t, i) => (
            <span key={i} className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              {t.label}
              <TxLink hash={t.hash} />
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

function StatusChip({ status }: { status: string }) {
  const color =
    status === "ready" ? "text-emerald-400 border-emerald-400/40"
    : status === "failed" ? "text-red-400 border-red-400/40"
    : "text-[#2563eb] border-[#2563eb]/40"
  return <span className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${color}`}>{status}</span>
}

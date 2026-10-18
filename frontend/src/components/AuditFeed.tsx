// A live view onto the real audit log (GET /audit/log) -- every entry
// shown here is a genuine, signed, hash-chained row from the backend, not
// a mockup. Used both as a compact "this just got logged" widget embedded
// in each portal, and (in non-compact form) as the full Audit Trail page.
import { useEffect, useState } from "react";
import { ChevronDown, ChevronRight, ScrollText } from "lucide-react";
import { api, type AuditEntry } from "../api/client";

const EVENT_STYLE: Record<string, string> = {
  issuance_started: "border-violet-800 bg-violet-950/40 text-violet-300",
  commitments_published: "border-violet-800 bg-violet-950/40 text-violet-300",
  share_issued: "border-violet-800 bg-violet-950/40 text-violet-300",
  recovery_requested: "border-amber-800 bg-amber-950/40 text-amber-300",
  recovery_refused: "border-rose-800 bg-rose-950/40 text-rose-300",
  share_approved: "border-sky-800 bg-sky-950/40 text-sky-300",
  record_recovered: "border-emerald-800 bg-emerald-950/40 text-emerald-300",
};

function styleFor(eventType: string): string {
  return EVENT_STYLE[eventType] ?? "border-slate-700 bg-slate-800/50 text-slate-300";
}

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

interface AuditFeedProps {
  title?: string;
  limit?: number;
  filterActor?: string; // only entries whose actor_id matches
  filterRecordId?: string; // only entries whose data.record_id matches
  filterEventType?: string; // only entries whose event_type matches
  compact?: boolean;
  pollMs?: number;
  // Change this value (e.g. a counter, or a just-settled boolean) right
  // when a portal knows an action of its own just finished -- forces an
  // immediate re-fetch instead of waiting for the next timed poll, so
  // "what this just logged" doesn't lag behind the actual approve/request
  // click by up to a full pollMs.
  refreshSignal?: unknown;
}

export default function AuditFeed({
  title = "Audit trail",
  limit = 8,
  filterActor,
  filterRecordId,
  filterEventType,
  compact = true,
  pollMs = 4000,
  refreshSignal,
}: AuditFeedProps) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const all = await api.auditLog();
        if (cancelled) return;
        setError(null);
        setEntries(all);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    }
    load();
    const id = setInterval(load, pollMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pollMs, refreshSignal]);

  const filtered = entries
    .filter((e) => (filterActor ? e.actor_id === filterActor : true))
    .filter((e) => (filterRecordId ? (e.data as Record<string, unknown>)?.record_id === filterRecordId : true))
    .filter((e) => (filterEventType ? e.event_type === filterEventType : true))
    .sort((a, b) => b.seq - a.seq);
  const shown = limit ? filtered.slice(0, limit) : filtered;

  return (
    <div className={compact ? "rounded-2xl border border-slate-800 bg-slate-900/60 p-5" : ""}>
      {compact && (
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
          <ScrollText className="h-4 w-4" /> {title}
        </h2>
      )}
      {error && <p className="text-xs text-rose-400">Could not load the audit log: {error}</p>}
      {!error && shown.length === 0 && (
        <p className="text-xs text-slate-500">
          Nothing logged {filterActor || filterRecordId ? "for this yet" : "yet"}. Every action below appends a
          signed entry here the moment it happens.
        </p>
      )}
      <div className="space-y-1.5">
        {shown.map((e) => {
          const isOpen = expanded === e.seq;
          return (
            <div key={e.seq} className="rounded-lg border border-slate-800 bg-slate-950/50 text-xs">
              <button
                onClick={() => setExpanded(isOpen ? null : e.seq)}
                className="flex w-full items-center gap-2 px-2.5 py-1.5 text-left"
              >
                {isOpen ? (
                  <ChevronDown className="h-3 w-3 shrink-0 text-slate-500" />
                ) : (
                  <ChevronRight className="h-3 w-3 shrink-0 text-slate-500" />
                )}
                <span className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] ${styleFor(e.event_type)}`}>
                  {e.event_type}
                </span>
                <span className="truncate text-slate-400">{e.actor_id}</span>
                <span className="ml-auto shrink-0 whitespace-nowrap text-slate-600">{formatTime(e.timestamp)}</span>
              </button>
              {isOpen && (
                <div className="border-t border-slate-800 px-2.5 py-2 font-mono text-[11px] text-slate-400">
                  <div className="mb-1">
                    <span className="text-slate-600">seq </span>
                    {e.seq}
                    <span className="ml-3 text-slate-600">hash </span>
                    <span className="break-all text-slate-500">{e.entry_hash.slice(0, 24)}…</span>
                  </div>
                  <pre className="overflow-x-auto whitespace-pre-wrap break-all text-slate-300">
                    {JSON.stringify(e.data, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

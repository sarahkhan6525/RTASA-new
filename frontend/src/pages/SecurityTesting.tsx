// Live, click-to-run reproduction of Table III's seven functional/
// adversarial checks and one Table IV row -- every check here calls
// the real backend (POST /security-tests/run), which runs each one
// against a disposable scratch system built fresh for the request.
// Nothing here touches the real demo state: it's safe to run as many
// times as you like mid-presentation.
import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Bug, CheckCircle2, XCircle, Loader2, ShieldAlert } from "lucide-react";
import { api, type SecurityTestResult } from "../api/client";

function GroupBadge({ passed, total }: { passed: number; total: number }) {
  const ok = passed === total;
  return (
    <span
      className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
        ok ? "border-emerald-800 bg-emerald-950/40 text-emerald-300" : "border-rose-800 bg-rose-950/40 text-rose-300"
      }`}
    >
      {passed}/{total} as expected
    </span>
  );
}

function ResultRow({ r, index }: { r: SecurityTestResult; index: number }) {
  const [open, setOpen] = useState(false);
  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className="rounded-lg border border-slate-800 bg-slate-950/50"
    >
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-3 py-2 text-left text-sm">
        {r.passed ? (
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
        ) : (
          <XCircle className="h-4 w-4 shrink-0 text-rose-400" />
        )}
        <span className="font-medium text-slate-200">{r.label}</span>
        <span className="hidden text-xs text-slate-500 sm:inline">{r.mechanism}</span>
        <span className="ml-auto shrink-0 rounded border border-slate-700 bg-slate-900 px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-400">
          expected: {r.expect}
        </span>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <div className="border-t border-slate-800 px-3 py-2 text-xs text-slate-400">
              <div className="mb-1 text-slate-500">mechanism: {r.mechanism}</div>
              {r.detail}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default function SecurityTesting() {
  const [results, setResults] = useState<SecurityTestResult[] | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ranAt, setRanAt] = useState<Date | null>(null);

  async function run() {
    setRunning(true);
    setError(null);
    try {
      const res = await api.runSecurityTests();
      setResults(res.results);
      setRanAt(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }

  const groups = results
    ? Array.from(new Set(results.map((r) => r.group))).map((g) => ({
        group: g,
        items: results.filter((r) => r.group === g),
      }))
    : [];
  const allPassed = results ? results.every((r) => r.passed) : null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-semibold text-slate-100">
          <Bug className="h-5 w-5 text-violet-400" /> Security Testing
        </h1>
        <p className="mt-1 text-sm text-slate-500">
          A live reproduction of Table III's seven adversarial/functional checks plus one Table IV log-tampering
          row (Sec. V-B): not a static table, but an actual run against the real cryptographic code, each time you
          click.
        </p>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={run}
            disabled={running}
            className="flex items-center gap-2 rounded-xl bg-violet-600 px-4 py-2.5 text-sm font-semibold text-white disabled:bg-slate-700"
          >
            {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldAlert className="h-4 w-4" />}
            {running ? "Running every check…" : results ? "Run again" : "Run security tests now"}
          </button>
          {allPassed !== null && (
            <span
              className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                allPassed
                  ? "border-emerald-800 bg-emerald-950/40 text-emerald-300"
                  : "border-rose-800 bg-rose-950/40 text-rose-300"
              }`}
            >
              {allPassed ? `✓ All ${results!.length} checks behaved as specified` : "✗ One or more checks did not behave as expected"}
            </span>
          )}
          {ranAt && <span className="text-xs text-slate-500">last run {ranAt.toLocaleTimeString()}</span>}
        </div>
        <p className="mt-3 text-xs text-slate-500">
          Each run builds a disposable set of roles, one record, and an in-memory audit log just for this request.
          It never touches the real custodians, records, or audit trail your demo is using elsewhere. Click it
          as many times as you like.
        </p>
        {error && (
          <div className="mt-3 rounded-lg border border-rose-900/60 bg-rose-950/30 p-3 text-xs text-rose-300">{error}</div>
        )}
      </div>

      {groups.map(({ group, items }) => (
        <div key={group} className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">{group}</h2>
            <GroupBadge passed={items.filter((i) => i.passed).length} total={items.length} />
          </div>
          <div className="space-y-1.5">
            {items.map((r, i) => (
              <ResultRow key={r.id} r={r} index={i} />
            ))}
          </div>
        </div>
      ))}

      {!results && !running && (
        <div className="rounded-2xl border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">
          Nothing run yet. Click "Run security tests now" to reproduce Table III and Table IV live.
        </div>
      )}
    </div>
  );
}

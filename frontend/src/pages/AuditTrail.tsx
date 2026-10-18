import { useState } from "react";
import toast from "react-hot-toast";
import { ShieldCheck, ShieldAlert, FlaskConical, Loader2 } from "lucide-react";
import { api, type AuditVerifyResponse, type TamperDemoResponse } from "../api/client";
import AuditFeed from "../components/AuditFeed";

const EVENT_TYPES = [
  "issuance_started",
  "commitments_published",
  "share_issued",
  "recovery_requested",
  "recovery_refused",
  "share_approved",
  "record_recovered",
];

function VerifyBadge({ v }: { v: AuditVerifyResponse }) {
  return v.ok ? (
    <div className="flex items-center gap-2 text-emerald-300">
      <ShieldCheck className="h-4 w-4" /> Verified clean: hash chain, signatures, and checkpoints all check out
    </div>
  ) : (
    <div>
      <div className="flex items-center gap-2 text-rose-300">
        <ShieldAlert className="h-4 w-4" /> Problem detected
      </div>
      <ul className="mt-1 list-inside list-disc text-rose-400">
        {v.problems.map((p, i) => (
          <li key={i}>{p}</li>
        ))}
      </ul>
    </div>
  );
}

export default function AuditTrail() {
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResponse | null>(null);
  const [tampering, setTampering] = useState(false);
  const [tamperResult, setTamperResult] = useState<TamperDemoResponse | null>(null);
  const [eventFilter, setEventFilter] = useState("");

  async function runVerify() {
    setVerifying(true);
    try {
      const res = await api.auditVerify();
      setVerifyResult(res);
      toast[res.ok ? "success" : "error"](res.ok ? "Audit log verifies clean" : "Audit log has a problem");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setVerifying(false);
    }
  }

  async function runTamperDemo() {
    setTampering(true);
    try {
      const res = await api.tamperDemo();
      setTamperResult(res);
      toast.success("Tamper simulation complete. See below.");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setTampering(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Audit Trail</h1>
        <p className="mt-1 text-sm text-slate-500">
          Every action RTASA performs (role creation, issuance, requests, approvals, recoveries, and refusals)
          is appended here as a signed, hash-chained entry (Sec. IV-C). Nothing on this page is a mockup: this is
          the real log, read straight from the running backend.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">Integrity check</h2>
          <p className="mb-3 text-xs text-slate-500">
            Re-walks the entire chain: every entry's hash links to the previous one, every signature is re-verified
            against the acting role's key, and the latest checkpoint is compared against what custodians actually
            countersigned.
          </p>
          <button
            onClick={runVerify}
            disabled={verifying}
            className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-semibold text-white disabled:bg-slate-700"
          >
            {verifying ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            {verifying ? "Verifying…" : "Verify audit log now"}
          </button>
          {verifyResult && <div className="mt-3 text-sm">{<VerifyBadge v={verifyResult} />}</div>}
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
            Tamper-detection demo (Table IV)
          </h2>
          <p className="mb-3 text-xs text-slate-500">
            Takes a scratch copy of the real log, edits the most recent entry's data the way an attacker with
            log-host access but no signing keys could, and verifies that copy. Your real log is never touched.
          </p>
          <button
            onClick={runTamperDemo}
            disabled={tampering}
            className="flex items-center gap-2 rounded-lg border border-amber-700 bg-amber-950/30 px-4 py-2 text-sm font-semibold text-amber-300 hover:bg-amber-950/50 disabled:opacity-50"
          >
            {tampering ? <Loader2 className="h-4 w-4 animate-spin" /> : <FlaskConical className="h-4 w-4" />}
            {tampering ? "Running…" : "Simulate an insider edit"}
          </button>
          {tamperResult && (
            <div className="mt-3 space-y-2 text-xs">
              <p className="text-slate-400">{tamperResult.what_was_tampered}</p>
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="mb-1 font-semibold text-slate-300">Clean copy, before the edit:</div>
                <VerifyBadge v={tamperResult.clean_verify} />
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="mb-1 font-semibold text-slate-300">Same copy, after the edit:</div>
                <VerifyBadge v={tamperResult.tampered_verify} />
              </div>
              <p className="text-slate-500">{tamperResult.note}</p>
            </div>
          )}
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">All entries</h2>
          <select
            value={eventFilter}
            onChange={(e) => setEventFilter(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-300"
          >
            <option value="">All event types</option>
            {EVENT_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
        <AuditFeed compact={false} limit={0} filterEventType={eventFilter || undefined} pollMs={4000} />
      </div>
    </div>
  );
}

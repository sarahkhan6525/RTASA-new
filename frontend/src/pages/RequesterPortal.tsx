import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import { LogOut } from "lucide-react";
import { api, type RecordOut } from "../api/client";
import { getCredential } from "../lib/credStore";
import { clearSession, getSession } from "../lib/session";
import LiveSteps, { REQUEST_STEPS, RECOVERY_STEPS } from "../components/LiveSteps";
import AuditFeed from "../components/AuditFeed";

function b64dec(str: string): string {
  return decodeURIComponent(
    atob(str)
      .split("")
      .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
      .join("")
  );
}

export default function RequesterPortal() {
  const navigate = useNavigate();
  const session = getSession("requester")!;

  const [myRecords, setMyRecords] = useState<RecordOut[]>([]);
  const [selectedRecordId, setSelectedRecordId] = useState("");
  const [passphrase, setPassphrase] = useState(getCredential(session.role_id) ?? "");
  const [requestId, setRequestId] = useState<string | null>(null);
  const [requesting, setRequesting] = useState(false);
  const [requestSettled, setRequestSettled] = useState(false);
  const [approvedCount, setApprovedCount] = useState(0);
  const [recovering, setRecovering] = useState(false);
  const [recoverSettled, setRecoverSettled] = useState(false);
  const [recoverResult, setRecoverResult] = useState<string | null>(null);
  const [recoverBlocked, setRecoverBlocked] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // The request_id used to live only in this component's local state, so
    // signing out to let custodians approve (or just refreshing the tab)
    // made it invisible again -- the requester had no way back to "Attempt
    // recovery" without re-requesting from scratch and orphaning whatever
    // approvals the first request already had. Recover it from the real
    // backend instead: if this role already has an outstanding request,
    // resume straight into step 3 with it.
    Promise.all([api.listRecords(), api.listRecoveryRequests()])
      .then(([recs, reqs]) => {
        const mine = reqs
          .filter((r) => r.requester_role_id === session.role_id)
          .sort((a, b) => (a.request_id < b.request_id ? 1 : -1))[0]; // request_id is req-<timestamp>
        // Normally restricted to records this role is explicitly entitled
        // to, but an owner can also leave a record open to any requester
        // (empty entitled_requesters) -- if that's how this role got in,
        // it won't be in entitled_requesters, so always keep whatever
        // record its own outstanding request already points at.
        setMyRecords(
          recs.filter((r) => r.entitled_requesters.includes(session.role_id) || r.record_id === mine?.record_id)
        );
        if (mine) {
          setSelectedRecordId(mine.record_id);
          setRequestId(mine.request_id);
          setApprovedCount(mine.approvals_so_far);
        }
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [session.role_id]);

  const record = myRecords.find((r) => r.record_id === selectedRecordId) ?? null;
  const threshold = record?.threshold ?? 0;

  function selectRecord(id: string) {
    setSelectedRecordId(id);
    setRequestId(null);
    setApprovedCount(0);
    setRecoverResult(null);
    setRecoverBlocked(null);
    setError(null);
  }

  async function handleRequest() {
    if (!record) return;
    setRequesting(true);
    setRequestSettled(false);
    setError(null);
    try {
      const rid = `req-${Date.now()}`;
      const otp = await api.getOtp(session.role_id);
      await api.startRecovery({
        request_id: rid,
        record_id: record.record_id,
        requester_role_id: session.role_id,
        requester_passphrase: passphrase,
        requester_otp: otp.otp,
      });
      setRequestId(rid);
      toast.success("Access request sent to custodians");
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setError(message);
      toast.error(message);
    } finally {
      setRequesting(false);
      setRequestSettled(true);
    }
  }

  async function pollApprovals() {
    if (!requestId) return;
    try {
      const reqs = await api.listRecoveryRequests();
      const mine = reqs.find((r) => r.request_id === requestId);
      if (mine) setApprovedCount(mine.approvals_so_far);
    } catch {
      /* ignore -- next poll will retry */
    }
  }

  useEffect(() => {
    if (!requestId) return;
    pollApprovals();
    const id = setInterval(pollApprovals, 4000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestId]);

  async function handleRecover() {
    if (!requestId) return;
    setRecovering(true);
    setRecoverSettled(false);
    setRecoverResult(null);
    setRecoverBlocked(null);
    setError(null);
    try {
      const otp = await api.getOtp(session.role_id);
      const res = await api.recoverRecord({
        request_id: requestId,
        requester_passphrase: passphrase,
        requester_otp: otp.otp,
      });
      setRecoverSettled(true);
      setRecoverResult(b64dec(res.message_base64));
      toast.success("Record recovered");
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setRecoverSettled(true);
      setRecoverBlocked(message);
      toast.error("Access blocked. See details below.");
    } finally {
      setRecovering(false);
    }
  }

  function signOut() {
    clearSession();
    navigate("/");
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Requester Portal</h1>
          <p className="mt-1 text-sm text-slate-500">
            Signed in as <span className="text-slate-300">{session.display_name}</span>. Entitled to request{" "}
            {myRecords.length} record{myRecords.length === 1 ? "" : "s"}.
          </p>
        </div>
        <button
          onClick={signOut}
          className="flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-rose-600 hover:text-rose-300"
        >
          <LogOut className="h-3.5 w-3.5" /> Sign out
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-900/60 bg-rose-950/30 p-4 text-sm text-rose-300">{error}</div>
      )}

      {myRecords.length === 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 text-sm text-slate-500">
          No records currently list you as an entitled requester. Ask a record's owner to add your email in the
          "Entitled requesters" step when they protect a record.
        </div>
      ) : (
        <>
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">1. Pick a record</h2>
            <select
              value={selectedRecordId}
              onChange={(e) => selectRecord(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
            >
              <option value="">Select a record…</option>
              {myRecords.map((r) => (
                <option key={r.record_id} value={r.record_id}>
                  {r.record_id} ({r.threshold}-of-{r.n})
                </option>
              ))}
            </select>
          </div>

          {record && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">2. Request access</h2>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                disabled={!!requestId}
                placeholder="Your passphrase"
                className="mb-3 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 disabled:opacity-60"
              />
              <button
                onClick={handleRequest}
                disabled={!!requestId || requesting || passphrase.length < 12}
                className="w-full rounded-xl bg-violet-600 py-2.5 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                {requestId ? "✓ Request sent" : requesting ? "Requesting…" : "Request access"}
              </button>

              {(requesting || requestSettled) && (
                <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/50 p-3">
                  <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                    What "Request access" actually does
                  </p>
                  <LiveSteps steps={REQUEST_STEPS} running={requesting} settled={requestSettled} />
                </div>
              )}
            </div>
          )}

          {requestId && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">3. Waiting for custodians</h2>
              <div className="mb-4 text-center">
                <div className="text-lg font-semibold text-slate-100">
                  {approvedCount} / {threshold}
                </div>
                <div className={`text-xs font-medium ${approvedCount >= threshold ? "text-emerald-400" : "text-amber-400"}`}>
                  {approvedCount >= threshold ? "THRESHOLD REACHED" : "waiting for custodians to approve"}
                </div>
              </div>
              <button
                onClick={handleRecover}
                disabled={recovering}
                className="w-full rounded-xl bg-violet-600 py-2.5 text-sm font-semibold text-white disabled:bg-slate-700"
              >
                {recovering ? "Attempting recovery…" : "Attempt recovery"}
              </button>

              {(recovering || recoverSettled) && (
                <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/50 p-3">
                  <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                    What "Attempt recovery" actually does
                  </p>
                  <LiveSteps steps={RECOVERY_STEPS} running={recovering} settled={recoverSettled} />
                </div>
              )}

              {recoverBlocked && (
                <div className="mt-4 rounded-xl border border-rose-900/60 bg-rose-950/30 p-4 text-center">
                  <div className="text-sm font-semibold text-rose-300">✗ ACCESS BLOCKED</div>
                  <div className="mt-1 text-xs text-rose-400">{recoverBlocked}</div>
                </div>
              )}
              {recoverResult && (
                <div className="mt-4 rounded-xl border border-emerald-900/60 bg-emerald-950/20 p-4">
                  <div className="text-sm font-semibold text-emerald-300">✓ Record recovered</div>
                  <div className="mt-2 rounded-lg bg-slate-950 p-3 text-sm text-slate-200">"{recoverResult}"</div>
                </div>
              )}
            </div>
          )}
        </>
      )}

      <AuditFeed
        title="What this portal has logged"
        filterActor={session.role_id}
        limit={6}
        refreshSignal={`${requestId ?? ""}:${recoverSettled}`}
      />
    </div>
  );
}

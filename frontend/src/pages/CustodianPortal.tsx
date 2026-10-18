import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import { LogOut, Inbox } from "lucide-react";
import { api, type RecordOut, type RecoveryRequestOut, type RoleOut } from "../api/client";
import { getCredential } from "../lib/credStore";
import { clearSession, getSession } from "../lib/session";
import LiveSteps, { APPROVAL_STEPS } from "../components/LiveSteps";
import AuditFeed from "../components/AuditFeed";

export default function CustodianPortal() {
  const navigate = useNavigate();
  const session = getSession("custodian")!;

  const [myRecords, setMyRecords] = useState<RecordOut[]>([]);
  const [requests, setRequests] = useState<RecoveryRequestOut[]>([]);
  const [roles, setRoles] = useState<RoleOut[]>([]);
  const [passphrase, setPassphrase] = useState(getCredential(session.role_id) ?? "");
  const [approvingId, setApprovingId] = useState<string | null>(null);
  const [settledId, setSettledId] = useState<string | null>(null);
  const [lastApprovalsSoFar, setLastApprovalsSoFar] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    const [recs, reqs, rls] = await Promise.all([api.listRecords(), api.listRecoveryRequests(), api.listRoles()]);
    setMyRecords(recs.filter((r) => r.custodian_role_ids.includes(session.role_id)));
    setRequests(reqs.filter((r) => myRecordIds(recs).has(r.record_id)));
    setRoles(rls);
  }

  function myRecordIds(recs: RecordOut[]): Set<string> {
    return new Set(recs.filter((r) => r.custodian_role_ids.includes(session.role_id)).map((r) => r.record_id));
  }

  useEffect(() => {
    refresh().catch((e) => setError(e instanceof Error ? e.message : String(e)));
    const id = setInterval(() => refresh().catch(() => {}), 5000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const roleName = (rid: string) => roles.find((r) => r.role_id === rid)?.display_name ?? rid;

  const pending = requests.filter((r) => !r.threshold_met && !r.approving_roles.includes(session.role_id));
  const alreadyApproved = requests.filter((r) => r.approving_roles.includes(session.role_id) && !r.threshold_met);
  const resolved = requests.filter((r) => r.threshold_met);

  async function handleApprove(requestId: string) {
    if (passphrase.length < 12) {
      toast.error("Enter your passphrase first");
      return;
    }
    setApprovingId(requestId);
    setSettledId(null);
    setError(null);
    try {
      const otp = await api.getOtp(session.role_id);
      const res = await api.approveRecovery({
        request_id: requestId,
        custodian_role_id: session.role_id,
        custodian_passphrase: passphrase,
        custodian_otp: otp.otp,
      });
      setLastApprovalsSoFar(res.approvals_so_far);
      setSettledId(requestId);
      toast.success(`Approved (${res.approvals_so_far} approval${res.approvals_so_far === 1 ? "" : "s"} so far)`);
      await refresh();
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setSettledId(requestId);
      setError(message);
      toast.error(message);
    } finally {
      setApprovingId(null);
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
          <h1 className="text-xl font-semibold text-slate-100">Custodian Portal</h1>
          <p className="mt-1 text-sm text-slate-500">
            Signed in as <span className="text-slate-300">{session.display_name}</span>. You hold a share of{" "}
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

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">Your passphrase</h2>
        <p className="mb-2 text-xs text-slate-500">
          Needed to actually approve a request (your sign-in above only verified your identity for routing).
        </p>
        <input
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder="Your passphrase"
          className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
        />
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
          <Inbox className="h-4 w-4" /> Awaiting your approval ({pending.length})
        </h2>
        {pending.length === 0 ? (
          <p className="text-sm text-slate-500">Nothing pending right now. This list refreshes automatically.</p>
        ) : (
          <div className="space-y-2">
            {pending.map((r) => (
              <div key={r.request_id} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm">
                <div>
                  <div className="font-medium text-slate-200">{r.record_id}</div>
                  <div className="text-xs text-slate-500">
                    Requested by {roleName(r.requester_role_id)}: {r.approvals_so_far}/{r.threshold} approvals so far
                  </div>
                </div>
                <button
                  onClick={() => handleApprove(r.request_id)}
                  disabled={approvingId === r.request_id || passphrase.length < 12}
                  className="rounded-lg bg-violet-600 px-3 py-1.5 text-xs font-medium text-white disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
                >
                  {approvingId === r.request_id ? "Approving…" : "Approve"}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {(approvingId || settledId) && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
            Approving {requests.find((r) => r.request_id === (approvingId ?? settledId))?.record_id ?? "this request"}:
            what's actually happening
          </h2>
          <LiveSteps
            steps={APPROVAL_STEPS}
            running={!!approvingId}
            settled={!!settledId}
            liveValues={
              lastApprovalsSoFar != null
                ? { sign: `${lastApprovalsSoFar} approval${lastApprovalsSoFar === 1 ? "" : "s"} recorded so far` }
                : undefined
            }
          />
        </div>
      )}

      {(alreadyApproved.length > 0 || resolved.length > 0) && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Already handled</h2>
          <div className="space-y-2">
            {[...alreadyApproved, ...resolved].map((r) => (
              <div key={r.request_id} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-sm text-slate-400">
                <div>
                  {r.record_id}, requested by {roleName(r.requester_role_id)}
                </div>
                <div className={r.threshold_met ? "text-emerald-400" : "text-slate-500"}>
                  {r.threshold_met ? "✓ Threshold reached" : "✓ You approved"}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <AuditFeed
        title="What this portal has logged"
        filterActor={session.role_id}
        limit={6}
        refreshSignal={settledId}
      />
    </div>
  );
}

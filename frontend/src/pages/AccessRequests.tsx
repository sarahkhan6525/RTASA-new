import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import { api, type RecordOut, type RoleOut } from "../api/client";
import { getCredential, saveCredential } from "../lib/credStore";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">{title}</h2>
      {children}
    </div>
  );
}

function b64dec(str: string): string {
  return decodeURIComponent(
    atob(str)
      .split("")
      .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
      .join("")
  );
}

export default function AccessRequests() {
  const [records, setRecords] = useState<RecordOut[]>([]);
  const [roles, setRoles] = useState<RoleOut[]>([]);
  const [selectedRecordId, setSelectedRecordId] = useState("");
  const [error, setError] = useState<string | null>(null);

  const [requesterRoleId, setRequesterRoleId] = useState("");
  const [requesterPassphrase, setRequesterPassphrase] = useState("");
  const [requestId, setRequestId] = useState<string | null>(null);
  const [requesting, setRequesting] = useState(false);

  const [approvedCount, setApprovedCount] = useState(0);
  const [approvedRoles, setApprovedRoles] = useState<Set<string>>(new Set());
  const [custodianPassphrases, setCustodianPassphrases] = useState<Record<string, string>>({});
  const [approvingId, setApprovingId] = useState<string | null>(null);

  const [recovering, setRecovering] = useState(false);
  const [recoverResult, setRecoverResult] = useState<string | null>(null);
  const [recoverBlocked, setRecoverBlocked] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.listRecords(), api.listRoles()])
      .then(([recs, rls]) => {
        setRecords(recs);
        setRoles(rls);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const record = records.find((r) => r.record_id === selectedRecordId) ?? null;
  const roleName = (rid: string) => roles.find((r) => r.role_id === rid)?.display_name ?? rid;

  useEffect(() => {
    if (requesterRoleId) {
      const known = getCredential(requesterRoleId);
      if (known) setRequesterPassphrase(known);
    }
  }, [requesterRoleId]);

  function selectRecord(id: string) {
    setSelectedRecordId(id);
    setRequestId(null);
    setApprovedCount(0);
    setApprovedRoles(new Set());
    setRecoverResult(null);
    setRecoverBlocked(null);
    setError(null);
    const rec = records.find((r) => r.record_id === id);
    if (rec) {
      const prefill: Record<string, string> = {};
      for (const cid of rec.custodian_role_ids) {
        const known = getCredential(cid);
        if (known) prefill[cid] = known;
      }
      setCustodianPassphrases(prefill);
      if (rec.entitled_requesters.length > 0) setRequesterRoleId(rec.entitled_requesters[0]);
    }
  }

  async function handleRequest() {
    if (!record) return;
    setRequesting(true);
    setError(null);
    try {
      const rid = `req-${Date.now()}`;
      const otp = await api.getOtp(requesterRoleId);
      await api.startRecovery({
        request_id: rid,
        record_id: record.record_id,
        requester_role_id: requesterRoleId,
        requester_passphrase: requesterPassphrase,
        requester_otp: otp.otp,
      });
      // Only remember the passphrase once the backend has actually accepted
      // it -- saving it before this point risked persisting a wrong
      // passphrase to localStorage on a failed attempt, which getCredential
      // would then silently pre-fill into the field next time, leading the
      // user to unknowingly resubmit the same bad credential.
      saveCredential(requesterRoleId, requesterPassphrase);
      setRequestId(rid);
      toast.success("Access request sent to custodians");
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setError(message);
      toast.error(message);
    } finally {
      setRequesting(false);
    }
  }

  async function handleApprove(custodianId: string) {
    if (!requestId) return;
    setApprovingId(custodianId);
    setError(null);
    try {
      const pass = custodianPassphrases[custodianId] ?? "";
      const otp = await api.getOtp(custodianId);
      const res = await api.approveRecovery({
        request_id: requestId,
        custodian_role_id: custodianId,
        custodian_passphrase: pass,
        custodian_otp: otp.otp,
      });
      // Same reasoning as handleRequest above -- only save once the
      // backend has actually confirmed this passphrase is correct.
      saveCredential(custodianId, pass);
      setApprovedRoles((prev) => new Set(prev).add(custodianId));
      setApprovedCount(res.approvals_so_far);
      toast.success(`${roleName(custodianId)} approved (${res.approvals_so_far} so far)`);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setError(message);
      toast.error(message);
    } finally {
      setApprovingId(null);
    }
  }

  async function handleRecover() {
    if (!requestId) return;
    setRecovering(true);
    setRecoverResult(null);
    setRecoverBlocked(null);
    setError(null);
    try {
      const otp = await api.getOtp(requesterRoleId);
      const res = await api.recoverRecord({
        request_id: requestId,
        requester_passphrase: requesterPassphrase,
        requester_otp: otp.otp,
      });
      setRecoverResult(b64dec(res.message_base64));
      toast.success("Record recovered");
    } catch (e) {
      // A real rejection from the backend (e.g. ShareVerificationError below
      // threshold) -- not a canned message, this is whatever the API said.
      const message = e instanceof Error ? e.message : String(e);
      setRecoverBlocked(message);
      toast.error("Access blocked -- see details below");
    } finally {
      setRecovering(false);
    }
  }

  if (records.length === 0) {
    return (
      <div className="max-w-3xl">
        <h1 className="text-xl font-semibold text-slate-100">Access Requests</h1>
        <p className="mt-2 text-sm text-slate-500">
          {error ?? "No protected records yet -- go to Protect Record first and create one."}
        </p>
      </div>
    );
  }

  const threshold = record?.threshold ?? 0;
  const thresholdMet = approvedCount >= threshold;

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Access Requests</h1>
        <p className="mt-1 text-sm text-slate-500">
          A requester asks to unlock a record; custodians approve one at a time with their real
          passphrase and OTP. Nothing here is simulated -- every approve/recover click is a real
          backend call.
        </p>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-900/60 bg-rose-950/30 p-4 text-sm text-rose-300">
          {error}
        </div>
      )}

      <Section title="1. Pick a protected record">
        <select
          value={selectedRecordId}
          onChange={(e) => selectRecord(e.target.value)}
          className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
        >
          <option value="">Select a record…</option>
          {records.map((r) => (
            <option key={r.record_id} value={r.record_id}>
              {r.record_id} ({r.threshold}-of-{r.n})
            </option>
          ))}
        </select>
      </Section>

      {record && (
        <Section title="2. Request access">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <span className="mb-1 block text-xs text-slate-500">Requester role</span>
              <select
                value={requesterRoleId}
                onChange={(e) => setRequesterRoleId(e.target.value)}
                disabled={!!requestId}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 disabled:opacity-60"
              >
                {record.entitled_requesters.length === 0 && <option value="">No entitled requesters on this record</option>}
                {record.entitled_requesters.map((rid) => (
                  <option key={rid} value={rid}>
                    {roleName(rid)} ({rid})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <span className="mb-1 block text-xs text-slate-500">Requester passphrase</span>
              <input
                type="password"
                value={requesterPassphrase}
                onChange={(e) => setRequesterPassphrase(e.target.value)}
                disabled={!!requestId}
                placeholder="auto-filled if created on Protect Record"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 disabled:opacity-60"
              />
            </div>
          </div>
          <button
            onClick={handleRequest}
            disabled={!!requestId || requesting || !requesterRoleId || requesterPassphrase.length < 12}
            className="mt-3 w-full rounded-xl bg-violet-600 py-2.5 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {requestId ? "✓ Request sent" : requesting ? "Requesting…" : "Request access"}
          </button>
        </Section>
      )}

      {requestId && record && (
        <Section title="3. Custodian approvals">
          <div className="mb-3 text-center">
            <div className="text-lg font-semibold text-slate-100">
              {approvedCount} / {threshold}
            </div>
            <div className={`text-xs font-medium ${thresholdMet ? "text-emerald-400" : "text-amber-400"}`}>
              {thresholdMet ? "THRESHOLD REACHED" : "THRESHOLD NOT REACHED"}
            </div>
          </div>
          <div className="mb-4 flex justify-center gap-2">
            {record.custodian_role_ids.map((cid) => (
              <div key={cid} className="text-center">
                <div
                  className={`mx-auto h-4 w-4 rounded-full border-2 ${
                    approvedRoles.has(cid) ? "border-emerald-400 bg-emerald-400" : "border-slate-600"
                  }`}
                />
              </div>
            ))}
          </div>

          <div className="space-y-2">
            {record.custodian_role_ids.map((cid) => {
              const approved = approvedRoles.has(cid);
              return (
                <div
                  key={cid}
                  className={`flex items-center gap-2 rounded-lg border p-3 text-sm ${
                    approved ? "border-emerald-900/60 bg-emerald-950/20" : "border-slate-800 bg-slate-950/60"
                  }`}
                >
                  <div className="flex-1">
                    <div className="font-medium text-slate-200">
                      {roleName(cid)} <span className="text-xs text-slate-500">({cid})</span>
                    </div>
                  </div>
                  {!approved && (
                    <input
                      type="password"
                      value={custodianPassphrases[cid] ?? ""}
                      onChange={(e) =>
                        setCustodianPassphrases((p) => ({ ...p, [cid]: e.target.value }))
                      }
                      placeholder="passphrase"
                      className="w-44 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100"
                    />
                  )}
                  <button
                    onClick={() => handleApprove(cid)}
                    disabled={approved || approvingId === cid || !(custodianPassphrases[cid]?.length >= 12)}
                    className="rounded-lg border border-violet-700 px-3 py-1.5 text-xs font-medium text-violet-300 disabled:cursor-not-allowed disabled:border-slate-700 disabled:text-slate-500"
                  >
                    {approved ? "✓ Approved" : approvingId === cid ? "Approving…" : "Approve"}
                  </button>
                </div>
              );
            })}
          </div>
        </Section>
      )}

      {requestId && (
        <Section title="4. Recovery">
          <button
            onClick={handleRecover}
            disabled={recovering}
            className="w-full rounded-xl bg-violet-600 py-2.5 text-sm font-semibold text-white disabled:bg-slate-700"
          >
            {recovering ? "Attempting recovery…" : "Attempt recovery"}
          </button>
          <p className="mt-2 text-xs text-slate-500">
            This is a real call -- if fewer than {threshold} custodians have approved yet, your
            backend will genuinely reject it (not a canned message).
          </p>

          {recoverBlocked && (
            <div className="mt-4 rounded-xl border border-rose-900/60 bg-rose-950/30 p-4 text-center">
              <div className="text-sm font-semibold text-rose-300">✗ ACCESS BLOCKED</div>
              <div className="mt-1 text-xs text-rose-400">{recoverBlocked}</div>
            </div>
          )}

          {recoverResult && (
            <div className="mt-4 rounded-xl border border-emerald-900/60 bg-emerald-950/20 p-4">
              <div className="text-sm font-semibold text-emerald-300">✓ Record recovered</div>
              <div className="mt-2 rounded-lg bg-slate-950 p-3 text-sm text-slate-200">
                "{recoverResult}"
              </div>
            </div>
          )}
        </Section>
      )}
    </div>
  );
}

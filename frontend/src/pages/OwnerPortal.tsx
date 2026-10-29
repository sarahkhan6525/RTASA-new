import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import { LogOut, ShieldCheck } from "lucide-react";
import { api, type IssueRecordResponse, type RecordOut, type RoleOut } from "../api/client";
import { fileToBase64, generateDemoPassphrase, textToBase64 } from "../lib/util";
import { saveCredential } from "../lib/credStore";
import { clearSession, getSession } from "../lib/session";
import LiveSteps, { ISSUANCE_STEPS } from "../components/LiveSteps";
import AuditFeed from "../components/AuditFeed";

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function slug(name: string): string {
  const base = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
  const suffix = Math.random().toString(36).slice(2, 6);
  return `${base || "role"}-${suffix}`;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">{title}</h2>
      {children}
    </div>
  );
}

export default function OwnerPortal() {
  const navigate = useNavigate();
  const session = getSession("owner")!; // RequireSession guarantees this is non-null

  const [myRecords, setMyRecords] = useState<RecordOut[]>([]);
  const [roles, setRoles] = useState<RoleOut[]>([]);
  const [ownerPassphrase, setOwnerPassphrase] = useState("");

  const [recordName, setRecordName] = useState("");
  const [secretText, setSecretText] = useState("");
  const [mode, setMode] = useState<"text" | "file">("text");
  const [file, setFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const recordId = useMemo(() => `rec-${Date.now()}`, []);

  const [pendingCustodians, setPendingCustodians] = useState<
    { role_id: string; display_name: string; email: string; passphrase: string; evaluation_point: number }[]
  >([]);
  const [newCustodianName, setNewCustodianName] = useState("");
  const [newCustodianEmail, setNewCustodianEmail] = useState("");
  const [threshold, setThreshold] = useState(2);

  const [pendingRequesters, setPendingRequesters] = useState<
    { display_name: string; email: string; passphrase: string }[]
  >([]);
  const [newRequesterName, setNewRequesterName] = useState("");
  const [newRequesterEmail, setNewRequesterEmail] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const [issuingNow, setIssuingNow] = useState(false);
  const [issueSettled, setIssueSettled] = useState(false);
  const [progressLines, setProgressLines] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IssueRecordResponse | null>(null);

  useEffect(() => {
    Promise.all([api.listRecords(), api.listRoles()]).then(([recs, rls]) => {
      setMyRecords(recs.filter((r) => r.owner_role_id === session.role_id));
      setRoles(rls);
    });
  }, [session.role_id]);

  const existingCustodians = roles.filter((r) => r.is_custodian);
  const totalCustodianCount = pendingCustodians.length;
  const totalRequesterCount = pendingRequesters.length;

  function addPendingCustodian() {
    if (!newCustodianName.trim() || !isValidEmail(newCustodianEmail)) return;
    // Avoid colliding with any custodian's Shamir evaluation point already
    // in use anywhere in the system, not just ones added this session.
    const usedPoints = new Set<number>([
      ...existingCustodians
        .filter((r) => r.evaluation_point != null)
        .map((r) => r.evaluation_point as number),
      ...pendingCustodians.map((c) => c.evaluation_point),
    ]);
    let nextPoint = 1;
    while (usedPoints.has(nextPoint)) nextPoint++;
    setPendingCustodians((p) => [
      ...p,
      {
        role_id: slug(newCustodianName),
        display_name: newCustodianName.trim(),
        email: newCustodianEmail.trim(),
        passphrase: generateDemoPassphrase(),
        evaluation_point: nextPoint,
      },
    ]);
    setNewCustodianName("");
    setNewCustodianEmail("");
  }

  function addPendingRequester() {
    if (!newRequesterName.trim() || !isValidEmail(newRequesterEmail)) return;
    setPendingRequesters((p) => [
      ...p,
      { display_name: newRequesterName.trim(), email: newRequesterEmail.trim(), passphrase: generateDemoPassphrase() },
    ]);
    setNewRequesterName("");
    setNewRequesterEmail("");
  }

  const canSubmit =
    ownerPassphrase.length >= 12 &&
    totalCustodianCount >= 1 &&
    threshold >= 1 &&
    threshold <= totalCustodianCount &&
    totalRequesterCount >= 1 &&
    (mode === "text" ? secretText.trim().length > 0 : !!file) &&
    !submitting;

  async function handleSubmit() {
    setSubmitting(true);
    setAttempted(true);
    setIssuingNow(false);
    setIssueSettled(false);
    setError(null);
    setResult(null);
    const lines: string[] = [];
    const log = (s: string) => {
      lines.push(s);
      setProgressLines([...lines]);
    };
    try {
      const resolvedCustodianIds: string[] = [];
      for (const c of pendingCustodians) {
        log(`Creating custodian role "${c.display_name}" (x=${c.evaluation_point})...`);
        await api.createRole({
          role_id: c.role_id,
          display_name: c.display_name,
          email: c.email,
          passphrase: c.passphrase,
          is_custodian: true,
          evaluation_point: c.evaluation_point,
          notify_email: true,
        });
        saveCredential(c.role_id, c.passphrase);
        resolvedCustodianIds.push(c.role_id);
      }

      const resolvedRequesterIds: string[] = [];
      for (const r of pendingRequesters) {
        const rid = slug(r.display_name);
        log(`Creating requester role "${r.display_name}"...`);
        await api.createRole({
          role_id: rid,
          display_name: r.display_name,
          email: r.email,
          passphrase: r.passphrase,
          is_custodian: false,
          notify_email: true,
        });
        saveCredential(rid, r.passphrase);
        resolvedRequesterIds.push(rid);
      }

      log("Fetching your one-time code...");
      const otp = await api.getOtp(session.role_id);

      log(mode === "file" ? `Reading file "${file!.name}"...` : "Reading your text...");
      const message_base64 = mode === "file" ? await fileToBase64(file!) : textToBase64(secretText);

      log("Encrypting (AES-256-GCM), splitting the key (Shamir+Feldman), role-binding (RSA-OAEP), and embedding (steganography)...");
      setIssuingNow(true);
      const response = await api.issueRecord({
        owner_role_id: session.role_id,
        owner_passphrase: ownerPassphrase,
        owner_otp: otp.otp,
        record_id: recordId,
        message_base64,
        custodian_role_ids: resolvedCustodianIds,
        threshold,
        entitled_requesters: resolvedRequesterIds,
      });
      // Only remember the owner passphrase once issueRecord has actually
      // accepted it -- saving it earlier (before this, the only call that
      // validates owner_passphrase) risked persisting a wrong passphrase to
      // localStorage on a failed attempt, which would then be silently
      // pre-filled next time and resubmitted, unnoticed, by the owner.
      saveCredential(session.role_id, ownerPassphrase);
      setIssueSettled(true);
      log("Audit entries written for every step above.");
      setResult(response);
      toast.success(`Record protected (${response.threshold}-of-${response.custodian_role_ids.length})`);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setIssueSettled(true);
      setError(message);
      toast.error(message);
    } finally {
      setSubmitting(false);
      setIssuingNow(false);
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
          <h1 className="text-xl font-semibold text-slate-100">Owner Portal</h1>
          <p className="mt-1 text-sm text-slate-500">
            Signed in as <span className="text-slate-300">{session.display_name}</span>
          </p>
        </div>
        <button
          onClick={signOut}
          className="flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-rose-600 hover:text-rose-300"
        >
          <LogOut className="h-3.5 w-3.5" /> Sign out
        </button>
      </div>

      {myRecords.length > 0 && !result && (
        <Section title={`My records (${myRecords.length})`}>
          <div className="space-y-2">
            {myRecords.map((r) => (
              <div key={r.record_id} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm text-slate-300">
                {r.record_id}: {r.threshold}-of-{r.n}, {r.entitled_requesters.length} entitled requester(s)
              </div>
            ))}
          </div>
        </Section>
      )}

      {error && (
        <div className="rounded-xl border border-rose-900/60 bg-rose-950/30 p-4 text-sm text-rose-300">{error}</div>
      )}

      {result ? (
        <Section title="Record protected">
          <div className="rounded-xl border border-emerald-900/60 bg-emerald-950/20 p-4 text-center">
            <div className="flex items-center justify-center gap-2 text-sm font-semibold text-emerald-300">
              <ShieldCheck className="h-4 w-4" /> RTASA PROTECTION COMPLETE
            </div>
            <p className="mt-1 text-xs text-slate-400">
              {recordId} is now {result.threshold}-of-{result.custodian_role_ids.length}, role-bound and hidden
              across {result.custodian_role_ids.length} carrier images.
            </p>
          </div>

          <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/50 p-3">
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
              What that "Protect Record" call actually just did, in order
            </p>
            <LiveSteps
              steps={ISSUANCE_STEPS}
              running={false}
              settled
              liveValues={{
                feldman: `${result.feldman_commitments.length} commitments logged`,
                carrier: `${result.custodian_role_ids.length} carrier image(s) written`,
              }}
            />
          </div>

          {(pendingCustodians.length > 0 || pendingRequesters.length > 0) && (
            <div className="mt-4 rounded-xl border border-amber-900/50 bg-amber-950/20 p-4">
              <p className="mb-3 text-xs font-semibold text-amber-300">
                Sign-in details for the people you just created.
              </p>
              <div className="space-y-2">
                {pendingCustodians.map((c) => (
                  <div key={c.role_id} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5 text-xs">
                    <div className="text-slate-300">
                      <span className="font-semibold text-slate-100">{c.display_name}</span>: Custodian
                      portal (<a href="/login/custodian" className="underline decoration-dotted">/login/custodian</a>)
                    </div>
                    <div className="mt-1 font-mono text-slate-400">
                      {c.email} / {c.passphrase}
                    </div>
                  </div>
                ))}
                {pendingRequesters.map((r, i) => (
                  <div key={r.email + i} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5 text-xs">
                    <div className="text-slate-300">
                      <span className="font-semibold text-slate-100">{r.display_name}</span>: Requester
                      portal (<a href="/login/requester" className="underline decoration-dotted">/login/requester</a>)
                    </div>
                    <div className="mt-1 font-mono text-slate-400">
                      {r.email} / {r.passphrase}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <button
            onClick={() => window.location.reload()}
            className="mt-4 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-200 hover:border-violet-600"
          >
            Protect another record
          </button>
        </Section>
      ) : (
        <>
          <Section title="Upload or write the record">
            <div className="mb-3 flex gap-2">
              <button
                onClick={() => setMode("text")}
                className={`rounded-lg px-3 py-1.5 text-sm ${mode === "text" ? "bg-violet-600 text-white" : "bg-slate-800 text-slate-300"}`}
              >
                Paste text
              </button>
              <button
                onClick={() => setMode("file")}
                className={`rounded-lg px-3 py-1.5 text-sm ${mode === "file" ? "bg-violet-600 text-white" : "bg-slate-800 text-slate-300"}`}
              >
                Upload a file
              </button>
            </div>
            {mode === "text" ? (
              <textarea
                value={secretText}
                onChange={(e) => setSecretText(e.target.value)}
                className="min-h-[90px] w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm text-slate-100 outline-none focus:border-violet-600"
              />
            ) : (
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="flex min-h-[90px] w-full cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed border-slate-700 bg-slate-950 text-sm text-slate-400 hover:border-violet-600"
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  className="hidden"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
                {file ? `${file.name} (${(file.size / 1024).toFixed(1)} KB)` : "Click to choose a file"}
              </button>
            )}
            <input
              value={recordName}
              onChange={(e) => setRecordName(e.target.value)}
              placeholder="Record name (optional)"
              className="mt-3 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
            />
          </Section>

          <Section title="Confirm your passphrase">
            <p className="mb-2 text-xs text-slate-500">
              Needed to actually sign this issuance (the sign-in step above only verified your identity for
              routing).
            </p>
            <input
              type="password"
              value={ownerPassphrase}
              onChange={(e) => setOwnerPassphrase(e.target.value)}
              placeholder="Your passphrase"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
            />
          </Section>

          <Section title="Custodians and threshold">
            <div className="mb-3 flex flex-wrap gap-2">
              {pendingCustodians.map((c, i) => (
                <span key={c.role_id} className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-800/70 px-3 py-1 text-xs text-slate-200">
                  {c.display_name}
                  <button onClick={() => setPendingCustodians((p) => p.filter((_, idx) => idx !== i))} className="text-slate-500 hover:text-rose-400">
                    ×
                  </button>
                </span>
              ))}
            </div>
            <div className="flex gap-2">
              <input
                value={newCustodianName}
                onChange={(e) => setNewCustodianName(e.target.value)}
                placeholder="New custodian, e.g. Doctor"
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
              />
              <input
                type="email"
                value={newCustodianEmail}
                onChange={(e) => setNewCustodianEmail(e.target.value)}
                placeholder="Their email"
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
                onKeyDown={(e) => e.key === "Enter" && addPendingCustodian()}
              />
              <button
                onClick={addPendingCustodian}
                disabled={!newCustodianName.trim() || !isValidEmail(newCustodianEmail)}
                className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:border-violet-600 disabled:opacity-40"
              >
                Add
              </button>
            </div>
            <div className="mt-4">
              <div className="mb-1 text-sm text-slate-400">Threshold: {threshold}</div>
              <input
                type="range"
                min={1}
                max={Math.max(totalCustodianCount, 1)}
                value={Math.min(threshold, Math.max(totalCustodianCount, 1))}
                onChange={(e) => setThreshold(Number(e.target.value))}
                className="w-full accent-violet-500"
              />
            </div>
          </Section>

          <Section title="Entitled requesters">
            <div className="mb-3 flex flex-wrap gap-2">
              {pendingRequesters.map((r, i) => (
                <span key={r.display_name + i} className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-800/70 px-3 py-1 text-xs text-slate-200">
                  {r.display_name}
                  <button onClick={() => setPendingRequesters((p) => p.filter((_, idx) => idx !== i))} className="text-slate-500 hover:text-rose-400">
                    ×
                  </button>
                </span>
              ))}
            </div>
            <div className="flex gap-2">
              <input
                value={newRequesterName}
                onChange={(e) => setNewRequesterName(e.target.value)}
                placeholder="New requester, e.g. Attending Physician"
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
              />
              <input
                type="email"
                value={newRequesterEmail}
                onChange={(e) => setNewRequesterEmail(e.target.value)}
                placeholder="Their email"
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
                onKeyDown={(e) => e.key === "Enter" && addPendingRequester()}
              />
              <button
                onClick={addPendingRequester}
                disabled={!newRequesterName.trim() || !isValidEmail(newRequesterEmail)}
                className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:border-violet-600 disabled:opacity-40"
              >
                Add
              </button>
            </div>
          </Section>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <button
              disabled={!canSubmit}
              onClick={handleSubmit}
              className="w-full rounded-xl bg-violet-600 py-3 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
            >
              {submitting ? "Protecting record…" : "Protect Record"}
            </button>
            {progressLines.length > 0 && (
              <div className="mt-4 space-y-1 text-xs text-slate-400">
                {progressLines.map((l, i) => (
                  <div key={i}>→ {l}</div>
                ))}
              </div>
            )}
            {(issuingNow || issueSettled) && (
              <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/50 p-3">
                <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                  What that "Protect Record" call actually does, in order
                </p>
                <LiveSteps steps={ISSUANCE_STEPS} running={issuingNow} settled={issueSettled} />
              </div>
            )}
          </div>
        </>
      )}

      {attempted && (
        <AuditFeed
          title="What this just logged"
          filterActor={session.role_id}
          limit={6}
          refreshSignal={issueSettled}
        />
      )}
    </div>
  );
}

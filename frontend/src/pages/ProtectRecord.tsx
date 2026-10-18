import { useEffect, useMemo, useState } from "react";
import toast from "react-hot-toast";
import { ShieldCheck } from "lucide-react";
import { api, type IssueRecordResponse, type RoleOut } from "../api/client";
import { fileToBase64, generateDemoPassphrase, textToBase64 } from "../lib/util";
import { saveCredential } from "../lib/credStore";

function slug(name: string): string {
  const base = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
  const suffix = Math.random().toString(36).slice(2, 6);
  return `${base || "role"}-${suffix}`;
}

interface NewRoleDraft {
  display_name: string;
  email: string;
  passphrase: string;
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function RoleChip({ role, onRemove }: { role: RoleOut; onRemove?: () => void }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-800/70 px-3 py-1 text-xs text-slate-200">
      {role.display_name}
      <span className="text-slate-500">({role.role_id})</span>
      {onRemove && (
        <button onClick={onRemove} className="text-slate-500 hover:text-rose-400">
          ×
        </button>
      )}
    </span>
  );
}

export default function ProtectRecord() {
  const [roles, setRoles] = useState<RoleOut[]>([]);
  const [loadingRoles, setLoadingRoles] = useState(true);

  // record content
  const [recordName, setRecordName] = useState("");
  const [classification, setClassification] = useState("Sensitive / Confidential");
  const [mode, setMode] = useState<"text" | "file">("text");
  const [secretText, setSecretText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const recordId = useMemo(() => `rec-${Date.now()}`, []);

  // owner
  const [ownerRoleId, setOwnerRoleId] = useState<string>("");
  const [newOwner, setNewOwner] = useState<NewRoleDraft | null>(null);
  const [existingOwnerPassphrase, setExistingOwnerPassphrase] = useState("");

  // custodians + threshold
  const [custodianIds, setCustodianIds] = useState<string[]>([]);
  const [pendingCustodians, setPendingCustodians] = useState<
    { role_id: string; display_name: string; email: string; passphrase: string; evaluation_point: number }[]
  >([]);
  const [newCustodianName, setNewCustodianName] = useState("");
  const [newCustodianEmail, setNewCustodianEmail] = useState("");
  const [threshold, setThreshold] = useState(2);

  // requesters
  const [requesterIds, setRequesterIds] = useState<string[]>([]);
  const [newRequesterName, setNewRequesterName] = useState("");
  const [newRequesterEmail, setNewRequesterEmail] = useState("");
  const [pendingRequesters, setPendingRequesters] = useState<NewRoleDraft[]>([]);

  // submit state
  const [submitting, setSubmitting] = useState(false);
  const [progressLines, setProgressLines] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IssueRecordResponse | null>(null);

  useEffect(() => {
    api
      .listRoles()
      .then(setRoles)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoadingRoles(false));
  }, []);

  const existingCustodians = roles.filter((r) => r.is_custodian);
  const existingNonCustodians = roles.filter((r) => !r.is_custodian);

  const totalCustodianCount = custodianIds.length + pendingCustodians.length;
  const totalRequesterCount = requesterIds.length + pendingRequesters.length;

  function addPendingCustodian() {
    if (!newCustodianName.trim() || !isValidEmail(newCustodianEmail)) return;
    const usedPoints = new Set<number>([
      ...existingCustodians
        .filter((r) => custodianIds.includes(r.role_id) && r.evaluation_point != null)
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
    (newOwner
      ? !!newOwner.display_name.trim() && isValidEmail(newOwner.email)
      : !!ownerRoleId && existingOwnerPassphrase.length >= 12) &&
    totalCustodianCount >= 1 &&
    threshold >= 1 &&
    threshold <= totalCustodianCount &&
    totalRequesterCount >= 1 &&
    (mode === "text" ? secretText.trim().length > 0 : !!file) &&
    !submitting;

  async function handleSubmit() {
    setSubmitting(true);
    setError(null);
    setResult(null);
    const lines: string[] = [];
    const log = (s: string) => {
      lines.push(s);
      setProgressLines([...lines]);
    };

    try {
      // 1. create any brand-new roles first
      let resolvedOwnerId = ownerRoleId;
      if (newOwner) {
        resolvedOwnerId = slug(newOwner.display_name);
        log(`Creating owner role "${newOwner.display_name}"...`);
        await api.createRole({
          role_id: resolvedOwnerId,
          display_name: newOwner.display_name,
          email: newOwner.email,
          passphrase: newOwner.passphrase,
          is_custodian: false,
        });
        saveCredential(resolvedOwnerId, newOwner.passphrase);
      }

      const resolvedCustodianIds = [...custodianIds];
      for (const c of pendingCustodians) {
        log(`Creating custodian role "${c.display_name}" (x=${c.evaluation_point})...`);
        await api.createRole({
          role_id: c.role_id,
          display_name: c.display_name,
          email: c.email,
          passphrase: c.passphrase,
          is_custodian: true,
          evaluation_point: c.evaluation_point,
        });
        saveCredential(c.role_id, c.passphrase);
        resolvedCustodianIds.push(c.role_id);
      }

      const resolvedRequesterIds = [...requesterIds];
      for (const r of pendingRequesters) {
        const rid = slug(r.display_name);
        log(`Creating requester role "${r.display_name}"...`);
        await api.createRole({
          role_id: rid,
          display_name: r.display_name,
          email: r.email,
          passphrase: r.passphrase,
          is_custodian: false,
        });
        saveCredential(rid, r.passphrase);
        resolvedRequesterIds.push(rid);
      }

      // 2. owner credential + fresh OTP
      log("Fetching owner's one-time code...");
      const ownerPassphrase = newOwner ? newOwner.passphrase : existingOwnerPassphrase;
      if (!newOwner) saveCredential(resolvedOwnerId, existingOwnerPassphrase);
      const otp = await api.getOtp(resolvedOwnerId);

      // 3. encode message
      log(mode === "file" ? `Reading file "${file!.name}"...` : "Reading your text...");
      const message_base64 = mode === "file" ? await fileToBase64(file!) : textToBase64(secretText);

      // 4. the real, single atomic backend call that performs all five layers
      log("Encrypting (AES-256-GCM), splitting the key (Shamir+Feldman), role-binding (RSA-OAEP), and embedding (steganography)...");
      const response = await api.issueRecord({
        owner_role_id: resolvedOwnerId,
        owner_passphrase: ownerPassphrase,
        owner_otp: otp.otp,
        record_id: recordId,
        message_base64,
        custodian_role_ids: resolvedCustodianIds,
        threshold,
        entitled_requesters: resolvedRequesterIds,
      });
      log("Audit entries written for every step above.");
      setResult(response);
      setCustodianIds(resolvedCustodianIds);
      setRequesterIds(resolvedRequesterIds);
      toast.success(`Record protected (${response.threshold}-of-${response.custodian_role_ids.length})`);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setError(message);
      toast.error(message);
    } finally {
      setSubmitting(false);
    }
  }

  if (result) {
    return <ProtectionComplete recordId={recordId} name={recordName || recordId} response={result} />;
  }

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Protect a Record</h1>
        <p className="mt-1 text-sm text-slate-500">
          This runs the real pipeline on your backend: AES-256-GCM → Shamir+Feldman →
          role-bound RSA-OAEP → steganographic embedding → signed audit entries.
        </p>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-900/60 bg-rose-950/30 p-4 text-sm text-rose-300">
          {error}
        </div>
      )}

      {/* Step 1 */}
      <Section title="Step 1 — Upload or write the record">
        <div className="mb-3 flex gap-2">
          <TabButton active={mode === "text"} onClick={() => setMode("text")}>
            Paste text
          </TabButton>
          <TabButton active={mode === "file"} onClick={() => setMode("file")}>
            Upload a file
          </TabButton>
        </div>
        {mode === "text" ? (
          <textarea
            value={secretText}
            onChange={(e) => setSecretText(e.target.value)}
            placeholder="This patient's diagnosis must stay confidential until two of the three reviewing doctors approve its release."
            className="min-h-[90px] w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm text-slate-100 outline-none focus:border-violet-600"
          />
        ) : (
          <label className="flex min-h-[90px] cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed border-slate-700 bg-slate-950 text-sm text-slate-400 hover:border-violet-600">
            <input
              type="file"
              className="hidden"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
            {file ? `${file.name} (${(file.size / 1024).toFixed(1)} KB)` : "Click to choose a file"}
          </label>
        )}
        <div className="mt-3 grid grid-cols-2 gap-3">
          <Field label="Record name">
            <input
              value={recordName}
              onChange={(e) => setRecordName(e.target.value)}
              placeholder="patient_report_001"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-violet-600"
            />
          </Field>
          <Field label="Classification (label only)">
            <select
              value={classification}
              onChange={(e) => setClassification(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-violet-600"
            >
              <option>Sensitive / Confidential</option>
              <option>Internal</option>
              <option>Restricted</option>
            </select>
          </Field>
        </div>
        <p className="mt-2 text-xs text-slate-600">
          Record ID (auto-generated): <code className="text-slate-400">{recordId}</code>
        </p>
      </Section>

      {/* Owner */}
      <Section title="Data owner">
        {loadingRoles ? (
          <p className="text-sm text-slate-500">Loading roles…</p>
        ) : (
          <div className="space-y-2">
            <select
              value={newOwner ? "__new__" : ownerRoleId}
              onChange={(e) => {
                if (e.target.value === "__new__") {
                  setNewOwner({ display_name: "", email: "", passphrase: generateDemoPassphrase() });
                  setOwnerRoleId("");
                  setExistingOwnerPassphrase("");
                } else {
                  setNewOwner(null);
                  setOwnerRoleId(e.target.value);
                }
              }}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
            >
              <option value="">Select an existing role…</option>
              {existingNonCustodians.map((r) => (
                <option key={r.role_id} value={r.role_id}>
                  {r.display_name} ({r.role_id})
                </option>
              ))}
              <option value="__new__">+ Create a new owner role</option>
            </select>
            {newOwner && (
              <div className="rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm space-y-2">
                <input
                  value={newOwner.display_name}
                  onChange={(e) => setNewOwner({ ...newOwner, display_name: e.target.value })}
                  placeholder="Display name, e.g. Dr. Khan"
                  className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-100"
                />
                <input
                  type="email"
                  value={newOwner.email}
                  onChange={(e) => setNewOwner({ ...newOwner, email: e.target.value })}
                  placeholder="Email (used to sign in to the Owner portal)"
                  className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-100"
                />
                <p className="text-xs text-slate-500">
                  Demo credential (you'll use this to act as this role elsewhere):{" "}
                  <code className="text-violet-400">{newOwner.passphrase}</code>
                </p>
              </div>
            )}
            {!newOwner && ownerRoleId && (
              <input
                type="password"
                value={existingOwnerPassphrase}
                onChange={(e) => setExistingOwnerPassphrase(e.target.value)}
                placeholder="This role's passphrase (needed to authenticate as owner)"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-violet-600"
              />
            )}
          </div>
        )}
      </Section>

      {/* Custodians + threshold */}
      <Section title="Step 2 — Custodians and threshold">
        <div className="mb-3 flex flex-wrap gap-2">
          {existingCustodians.map((r) => {
            const picked = custodianIds.includes(r.role_id);
            return (
              <button
                key={r.role_id}
                onClick={() =>
                  setCustodianIds((ids) =>
                    picked ? ids.filter((x) => x !== r.role_id) : [...ids, r.role_id]
                  )
                }
                className={`rounded-full border px-3 py-1 text-xs ${
                  picked
                    ? "border-violet-500 bg-violet-500/10 text-violet-300"
                    : "border-slate-700 text-slate-300 hover:border-slate-500"
                }`}
              >
                {r.display_name} (x={r.evaluation_point})
              </button>
            );
          })}
          {pendingCustodians.map((c, i) => (
            <RoleChip
              key={c.role_id}
              role={{ ...c, is_custodian: true } as RoleOut}
              onRemove={() => setPendingCustodians((p) => p.filter((_, idx) => idx !== i))}
            />
          ))}
        </div>
        <div className="flex gap-2">
          <input
            value={newCustodianName}
            onChange={(e) => setNewCustodianName(e.target.value)}
            placeholder="New custodian, e.g. Doctor, Auditor, Legal"
            className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
          />
          <input
            type="email"
            value={newCustodianEmail}
            onChange={(e) => setNewCustodianEmail(e.target.value)}
            placeholder="Their email (for sign-in + notifications)"
            className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
            onKeyDown={(e) => e.key === "Enter" && addPendingCustodian()}
          />
          <button
            onClick={addPendingCustodian}
            disabled={!newCustodianName.trim() || !isValidEmail(newCustodianEmail)}
            className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:border-violet-600 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Add
          </button>
        </div>

        <div className="mt-4">
          <div className="mb-1 flex items-center justify-between text-sm">
            <span className="text-slate-400">
              Threshold — {threshold} of {totalCustodianCount || "?"} approvals required
            </span>
          </div>
          <input
            type="range"
            min={1}
            max={Math.max(totalCustodianCount, 1)}
            value={Math.min(threshold, Math.max(totalCustodianCount, 1))}
            onChange={(e) => setThreshold(Number(e.target.value))}
            className="w-full accent-violet-500"
          />
          <div className="mt-2 flex gap-1">
            {Array.from({ length: totalCustodianCount }).map((_, i) => (
              <span
                key={i}
                className={`h-2 flex-1 rounded ${i < threshold ? "bg-violet-500" : "bg-slate-800"}`}
              />
            ))}
          </div>
        </div>
      </Section>

      {/* Requesters */}
      <Section title="Entitled requesters">
        <div className="mb-3 flex flex-wrap gap-2">
          {existingNonCustodians
            .filter((r) => r.role_id !== ownerRoleId)
            .map((r) => {
              const picked = requesterIds.includes(r.role_id);
              return (
                <button
                  key={r.role_id}
                  onClick={() =>
                    setRequesterIds((ids) =>
                      picked ? ids.filter((x) => x !== r.role_id) : [...ids, r.role_id]
                    )
                  }
                  className={`rounded-full border px-3 py-1 text-xs ${
                    picked
                      ? "border-violet-500 bg-violet-500/10 text-violet-300"
                      : "border-slate-700 text-slate-300 hover:border-slate-500"
                  }`}
                >
                  {r.display_name}
                </button>
              );
            })}
          {pendingRequesters.map((r, i) => (
            <RoleChip
              key={r.display_name + i}
              role={{ role_id: slug(r.display_name), display_name: r.display_name, is_custodian: false, evaluation_point: null }}
              onRemove={() => setPendingRequesters((p) => p.filter((_, idx) => idx !== i))}
            />
          ))}
        </div>
        <div className="flex gap-2">
          <input
            value={newRequesterName}
            onChange={(e) => setNewRequesterName(e.target.value)}
            placeholder="New requester, e.g. Sarah Khan"
            className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
          />
          <input
            type="email"
            value={newRequesterEmail}
            onChange={(e) => setNewRequesterEmail(e.target.value)}
            placeholder="Their email (for sign-in)"
            className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
            onKeyDown={(e) => e.key === "Enter" && addPendingRequester()}
          />
          <button
            onClick={addPendingRequester}
            disabled={!newRequesterName.trim() || !isValidEmail(newRequesterEmail)}
            className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:border-violet-600 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Add
          </button>
        </div>
      </Section>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <button
          disabled={!canSubmit}
          onClick={handleSubmit}
          className="w-full rounded-xl bg-violet-600 py-3 text-sm font-semibold text-white transition disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
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
      </div>
    </div>
  );
}

function ProtectionComplete({
  recordId,
  name,
  response,
}: {
  recordId: string;
  name: string;
  response: IssueRecordResponse;
}) {
  return (
    <div className="max-w-3xl space-y-6">
      <div className="rounded-2xl border border-emerald-900/60 bg-emerald-950/20 p-6 text-center">
        <div className="flex items-center justify-center gap-2 text-lg font-semibold text-emerald-300">
          <ShieldCheck className="h-5 w-5" strokeWidth={2} />
          RTASA PROTECTION COMPLETE
        </div>
        <p className="mt-1 text-sm text-slate-400">
          {name} ({recordId}) is now encrypted, split {response.threshold}-of-
          {response.custodian_role_ids.length}, role-bound, and hidden across{" "}
          {response.custodian_role_ids.length} carrier images.
        </p>
      </div>

      <Section title="Shares generated">
        <p className="mb-3 text-xs text-slate-500">
          The polynomial's {response.feldman_commitments.length} public commitment point
          {response.feldman_commitments.length === 1 ? "" : "s"} (C₀…C
          {response.feldman_commitments.length - 1}) let anyone verify a share is genuine without
          learning the key -- they're shared across all {response.custodian_role_ids.length} shares
          below, not one-per-share.
        </p>
        <div className="space-y-2">
          {response.custodian_role_ids.map((rid, i) => (
            <div
              key={rid}
              className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm"
            >
              <div>
                <div className="font-medium text-slate-200">{rid}</div>
                <div className="text-xs text-slate-500">Share SH-{String(i + 1).padStart(3, "0")}</div>
              </div>
              <div className="text-right text-xs text-emerald-400">
                ✓ Feldman verified
                <br />✓ RSA-OAEP wrapped
                <br />✓ Embedded
              </div>
            </div>
          ))}
        </div>
      </Section>

      <Section title="Carrier images (real steganographic output)">
        <div className="grid grid-cols-3 gap-3">
          {response.custodian_role_ids.map((rid) => (
            <figure key={rid} className="text-center">
              <img
                src={api.carrierUrl(response.record_id, rid)}
                alt={`carrier for ${rid}`}
                className="w-full rounded-lg border border-slate-800"
              />
              <figcaption className="mt-1 text-xs text-slate-500">{rid}</figcaption>
            </figure>
          ))}
        </div>
      </Section>

      <button
        onClick={() => window.location.reload()}
        className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-200 hover:border-violet-600"
      >
        Protect another record
      </button>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">{title}</h2>
      {children}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs text-slate-500">{label}</span>
      {children}
    </label>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-lg px-3 py-1.5 text-sm ${
        active ? "bg-violet-600 text-white" : "bg-slate-800 text-slate-300 hover:bg-slate-700"
      }`}
    >
      {children}
    </button>
  );
}

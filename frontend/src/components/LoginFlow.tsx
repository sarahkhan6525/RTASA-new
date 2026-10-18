import { useState } from "react";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import { Mail, ShieldCheck, UserPlus } from "lucide-react";
import { api } from "../api/client";
import { saveCredential } from "../lib/credStore";
import { saveSession, type PortalKind } from "../lib/session";

interface LoginFlowProps {
  kind: PortalKind;
  title: string;
  subtitle: string;
  portalPath: string; // where to land after a successful verify
  allowCreate?: boolean; // let a brand-new person self-register for this role right here
}

const ROLE_LABEL: Record<PortalKind, string> = {
  owner: "Owner",
  custodian: "Custodian",
  requester: "Requester",
};

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

function slug(name: string, kind: PortalKind): string {
  const base = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
  const suffix = Math.random().toString(36).slice(2, 6);
  return `${base || kind}-${suffix}`;
}

// Custodian roles each need a distinct Shamir evaluation point (x_i, Sec.
// IV-A) -- a self-registering custodian can't know or choose this, so we
// pick the smallest free positive integer across every custodian role that
// already exists, exactly the same "first gap" rule the Owner Portal uses
// when it creates a custodian inline.
async function nextFreeEvaluationPoint(): Promise<number> {
  const roles = await api.listRoles();
  const used = new Set(
    roles.filter((r) => r.is_custodian && r.evaluation_point != null).map((r) => r.evaluation_point as number)
  );
  let point = 1;
  while (used.has(point)) point++;
  return point;
}

export default function LoginFlow({ kind, title, subtitle, portalPath, allowCreate }: LoginFlowProps) {
  const roleLabel = ROLE_LABEL[kind];
  const navigate = useNavigate();
  const [step, setStep] = useState<"credentials" | "code">("credentials");
  const [email, setEmail] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [code, setCode] = useState("");
  const [roleId, setRoleId] = useState("");
  const [emailHint, setEmailHint] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Self-registration -- lets a brand-new person create their own account
  // (owner, custodian, or requester) with their own chosen passphrase right
  // here, instead of only ever being pre-created by someone else.
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [creating, setCreating] = useState(false);

  async function handleCreateAndLogin() {
    setCreating(true);
    setError(null);
    try {
      const role_id = slug(newName, kind);
      const is_custodian = kind === "custodian";
      // Custodian roles need a Shamir evaluation point (x_i) that nothing
      // about a self-registering person can supply -- work it out the same
      // way the Owner Portal does when it creates a custodian inline.
      const evaluation_point = is_custodian ? await nextFreeEvaluationPoint() : undefined;
      await api.createRole({
        role_id,
        display_name: newName.trim(),
        email: newEmail.trim(),
        passphrase: newPassphrase,
        is_custodian,
        ...(evaluation_point != null ? { evaluation_point } : {}),
      });
      saveCredential(role_id, newPassphrase);
      toast.success(`${roleLabel} account created for ${newName.trim()}`);
      // Flow straight into the normal email+passphrase login so the
      // real /auth/login + email-OTP path still runs, exactly as it
      // would for a returning role holder.
      setEmail(newEmail.trim());
      setPassphrase(newPassphrase);
      setShowCreate(false);
      const res = await api.authLogin({ email: newEmail.trim(), passphrase: newPassphrase });
      setRoleId(res.role_id);
      setEmailHint(res.email_hint);
      setStep("code");
      toast.success(`Code sent to ${res.email_hint}`);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setError(message);
      toast.error(message);
    } finally {
      setCreating(false);
    }
  }

  async function handleLogin() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.authLogin({ email: email.trim(), passphrase });
      setRoleId(res.role_id);
      setEmailHint(res.email_hint);
      setStep("code");
      toast.success(`Code sent to ${res.email_hint}`);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setError(message);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.authVerify({ role_id: roleId, code: code.trim() });
      if (kind === "custodian" && !res.is_custodian) {
        throw new Error(`'${res.display_name}' is not a custodian role. Try the Owner or Requester portal instead.`);
      }
      saveSession({
        token: res.token,
        role_id: res.role_id,
        display_name: res.display_name,
        is_custodian: res.is_custodian,
        kind,
      });
      toast.success(`Signed in as ${res.display_name}`);
      navigate(portalPath);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setError(message);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-md pt-16">
      <div className="text-center">
        <h1 className="text-xl font-semibold text-slate-100">{title}</h1>
        <p className="mt-1 text-sm text-slate-500">{subtitle}</p>
      </div>

      <div className="mt-8 rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        {error && (
          <div className="mb-4 rounded-lg border border-rose-900/60 bg-rose-950/30 p-3 text-xs text-rose-300">
            {error}
          </div>
        )}

        {step === "credentials" ? (
          <div className="space-y-3">
            <label className="block">
              <span className="mb-1 block text-xs text-slate-500">Email</span>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-violet-600"
                onKeyDown={(e) => e.key === "Enter" && handleLogin()}
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-slate-500">Passphrase</span>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-violet-600"
                onKeyDown={(e) => e.key === "Enter" && handleLogin()}
              />
            </label>
            <button
              onClick={handleLogin}
              disabled={loading || !email.trim() || passphrase.length < 1}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-violet-600 py-2.5 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
            >
              <Mail className="h-4 w-4" />
              {loading ? "Sending code…" : "Email me a sign-in code"}
            </button>

            {allowCreate && (
              <div className="pt-2">
                {!showCreate ? (
                  <button
                    onClick={() => setShowCreate(true)}
                    className="flex w-full items-center justify-center gap-1.5 text-xs text-slate-500 underline decoration-dotted hover:text-slate-300"
                  >
                    <UserPlus className="h-3.5 w-3.5" /> First time here? Create your {roleLabel.toLowerCase()} account
                  </button>
                ) : (
                  <div className="mt-3 space-y-2 rounded-xl border border-dashed border-slate-700 p-3">
                    <p className="text-xs text-slate-500">
                      Creates a new {roleLabel} role with this name, email, and passphrase, then signs
                      you straight into the same email-code step above.
                      {kind === "requester" &&
                        " A custodian (or the owner) will still need to approve any record you " +
                          "request access to. This just creates your sign-in."}
                    </p>
                    <input
                      value={newName}
                      onChange={(e) => setNewName(e.target.value)}
                      placeholder="Your name"
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
                    />
                    <input
                      type="email"
                      value={newEmail}
                      onChange={(e) => setNewEmail(e.target.value)}
                      placeholder="Your email"
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
                    />
                    <input
                      type="password"
                      value={newPassphrase}
                      onChange={(e) => setNewPassphrase(e.target.value)}
                      placeholder="Choose a passphrase (12+ characters)"
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
                    />
                    <button
                      onClick={handleCreateAndLogin}
                      disabled={
                        creating || !newName.trim() || !isValidEmail(newEmail) || newPassphrase.length < 12
                      }
                      className="flex w-full items-center justify-center gap-2 rounded-lg bg-slate-700 py-2 text-sm font-semibold text-slate-100 hover:bg-slate-600 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {creating ? "Creating…" : "Create account & continue"}
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-slate-500">
              A 6-digit code was sent to <span className="text-slate-300">{emailHint}</span>. Enter it below.
            </p>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="123456"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-center text-lg tracking-[0.5em] text-slate-100 outline-none focus:border-violet-600"
              onKeyDown={(e) => e.key === "Enter" && handleVerify()}
            />
            <button
              onClick={handleVerify}
              disabled={loading || code.length !== 6}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-violet-600 py-2.5 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
            >
              <ShieldCheck className="h-4 w-4" />
              {loading ? "Verifying…" : "Verify and sign in"}
            </button>
            <button
              onClick={() => {
                setStep("credentials");
                setCode("");
                setError(null);
              }}
              className="w-full text-center text-xs text-slate-500 underline decoration-dotted hover:text-slate-300"
            >
              Use a different email
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// The paper's own quantitative evaluation (Sec. V), laid out for a
// demo: Table III (functional/adversarial checks), Table IV (log
// tampering detection), Fig. 2 (latency), Fig. 3 (concealment), plus a
// live snapshot of this running backend. Tables III/IV mirror the
// corrected/justified paper (RTASA_LNCS_justified): the paper no longer
// claims literal 840/200-trial counts -- its real backing data is the
// 79-test automated pytest suite (tests/test_end_to_end.py), so these
// tables show pass/detect outcomes rather than invented trial counts.
// A direct link to the Security Testing tab lets you reproduce Table III
// and one Table IV row live, right now, against the real code.
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { BarChart3, CheckCircle2, XCircle, FileText, Users, ScrollText, ArrowRight } from "lucide-react";
import StatCard from "../components/StatCard";
import { api, type DashboardSummary } from "../api/client";

const TABLE_III = [
  { check: "Recover with any k approving roles", mechanism: "Lagrange + GCM" },
  { check: "Recover with k − 1 shares", mechanism: "GCM tag rejects" },
  { check: "Corrupted share value", mechanism: "Feldman check (4)" },
  { check: "Embedded bit flipped in carrier", mechanism: "OAEP decoding" },
  { check: "Share opened with another role's key", mechanism: "OAEP decoding" },
  { check: "Share replayed under another id", mechanism: "id binding in (5)" },
  { check: "Unentitled requester", mechanism: "Policy check" },
];

const TABLE_IV = [
  { attack: "Edit entry, no recomputation", plainDetected: true, rtasaDetected: true },
  { attack: "Edit entry, host recomputes chain", plainDetected: false, rtasaDetected: true },
  { attack: "Insider edits own entry, re-signs", plainDetected: false, rtasaDetected: true },
  { attack: "Insert forged entry, recompute", plainDetected: false, rtasaDetected: true },
  { attack: "Delete entry, no recomputation", plainDetected: true, rtasaDetected: true },
  { attack: "Truncate before last checkpoint", plainDetected: false, rtasaDetected: true },
  { attack: "Truncate after last checkpoint", plainDetected: false, rtasaDetected: false },
];

function PassBadge() {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-emerald-800 bg-emerald-950/40 px-2 py-0.5 text-xs font-medium text-emerald-300">
      <CheckCircle2 className="h-3 w-3" /> Pass
    </span>
  );
}

function OutcomeBadge({ detected }: { detected: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${
        detected
          ? "border-emerald-800 bg-emerald-950/40 text-emerald-300"
          : "border-rose-800 bg-rose-950/40 text-rose-300"
      }`}
    >
      {detected ? <CheckCircle2 className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
      {detected ? "Detected" : "Not detected"}
    </span>
  );
}

function RangeBar({ label, lo, hi, baseline, unit = "ms", max }: { label: string; lo: number; hi: number; baseline: number; unit?: string; max: number }) {
  const pct = (v: number) => Math.min(100, (v / max) * 100);
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between text-xs">
        <span className="font-medium text-slate-300">{label}</span>
        <span className="text-slate-500">
          {lo}–{hi} {unit} <span className="text-slate-600">(baseline {baseline} {unit})</span>
        </span>
      </div>
      <div className="relative h-2.5 w-full rounded-full bg-slate-800">
        <div
          className="absolute h-2.5 rounded-full bg-violet-500/70"
          style={{ left: `${pct(lo)}%`, width: `${pct(hi) - pct(lo)}%` }}
        />
        <div
          className="absolute top-[-3px] h-[18px] w-[2px] bg-slate-300"
          style={{ left: `${pct(baseline)}%` }}
          title={`plain-hybrid baseline: ${baseline} ${unit}`}
        />
      </div>
    </div>
  );
}

export default function Evaluation() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.dashboardSummary().then((s) => {
      if (!cancelled) setSummary(s);
    }).catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-semibold text-slate-100">
          <BarChart3 className="h-5 w-5 text-violet-400" /> Evaluation
        </h1>
        <p className="mt-1 text-sm text-slate-500">
          Section V's prototype evaluation (correctness, log-tampering detection, latency, and concealment),
          exactly as the paper reports it, alongside a live snapshot of this running backend.
        </p>
      </div>

      {summary && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Protected Records (live)" value={String(summary.protected_records)} icon={FileText} />
          <StatCard label="Active Custodians (live)" value={String(summary.active_custodians)} icon={Users} />
          <StatCard label="Audit Entries (live)" value={String(summary.audit_entries)} icon={ScrollText} />
          <StatCard
            label="Audit Integrity (live)"
            value={summary.audit_integrity_ok ? "✓ Verified" : "✗ Problem"}
            tone={summary.audit_integrity_ok ? "good" : "bad"}
          />
        </div>
      )}

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
              Table III: Functional checks (as reported, Sec. V-B)
            </h2>
            <p className="mt-1 text-xs text-slate-500">
              Automated pytest suite (<code className="text-slate-400">tests/test_end_to_end.py</code>, 79 tests
              total), run once for each of (k, n) = (2,3), (3,5), (5,7) — every test passed.
            </p>
          </div>
          <Link
            to="/console/security-tests"
            className="flex items-center gap-1 rounded-lg border border-violet-800 bg-violet-950/30 px-3 py-1.5 text-xs font-medium text-violet-300 hover:border-violet-500"
          >
            Run these checks live now <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
        <div className="space-y-1.5">
          {TABLE_III.map((row) => (
            <div key={row.check} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2 text-sm">
              <div>
                <span className="text-slate-200">{row.check}</span>
                <span className="ml-2 text-xs text-slate-500">{row.mechanism}</span>
              </div>
              <PassBadge />
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide text-slate-400">
          Table IV: Detection of log tampering (as reported, Sec. V-B)
        </h2>
        <p className="mb-3 text-xs text-slate-500">
          Seven attacks, each checked by the automated test suite at several tamper positions on 64-entry logs with
          a checkpoint every 8 entries. A plain hash chain misses every attack where the host recomputes hashes;
          RTASA detects all of them except truncation after the last checkpoint, the designed window.
        </p>
        <div className="space-y-1.5">
          {TABLE_IV.map((row) => (
            <div key={row.attack} className="flex items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2 text-sm">
              <span className="text-slate-200">{row.attack}</span>
              <div className="flex shrink-0 items-center gap-3 text-xs">
                <span className="text-slate-500">plain chain <OutcomeBadge detected={row.plainDetected} /></span>
                <span className="text-slate-500">RTASA <OutcomeBadge detected={row.rtasaDetected} /></span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide text-slate-400">
          Fig. 2: Latency for a 1 MiB record (as reported, Sec. V-C)
        </h2>
        <p className="mb-4 text-xs text-slate-500">
          Across (k, n) from (2,3) to (7,10), against AES-GCM + a single RSA-OAEP wrap (E + A only, no T/S/L),
          measured on a consumer laptop (Apple MacBook Air, Python 3.10.11). Embedding (S) dominates issuance;
          Feldman checks (T) and RSA private-key ops (A) dominate recovery. Even at ten custodians, recovery
          stays below 55 ms at the 90th percentile.
        </p>
        <div className="space-y-4">
          <RangeBar label="Issuance (I)" lo={11.7} hi={33.8} baseline={0.18} max={60} />
          <RangeBar label="Recovery (R)" lo={16.2} hi={53.8} baseline={0.70} max={60} />
        </div>
        <p className="mt-3 text-[11px] text-slate-600">
          The violet band is RTASA's range across (k,n) settings; the white tick is the plain-hybrid baseline.
        </p>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide text-slate-400">
          Fig. 3: Concealment (as reported, Sec. V-D)
        </h2>
        <p className="mb-4 text-xs text-slate-500">
          144 non-overlapping 256x256 Kodak crops, tested with RS analysis, SPA, and SPAM features + a learned
          shrinkage LDA detector, six-fold cross-validated grouped by source image.
        </p>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="PSNR of embedding" value="66.2 dB" />
          <StatCard label="Pixels changed" value="1.6%" />
          <StatCard label="SPA vs. LSB replacement" value="AUC 0.86" tone="bad" />
          <StatCard label="Structural detectors vs. RTASA" value="AUC ≤ 0.53" tone="good" />
        </div>
        <p className="mt-3 text-xs text-slate-500">
          SPA reliably detects the naive LSB <em>replacement</em> baseline (AUC 0.86), confirming the detector
          itself works, but both structural detectors stay at or near chance (AUC ≤ 0.53, chance = 0.50)
          against RTASA's actual LSB <em>matching</em> embedder at every rate tested. That's G3.
        </p>
      </div>
    </div>
  );
}

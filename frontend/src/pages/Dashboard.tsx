import { useEffect, useState } from "react";
import { FileText, Users, Gauge, Clock, ScrollText } from "lucide-react";
import StatCard from "../components/StatCard";
import Pipeline from "../components/Pipeline";
import { api, type DashboardSummary } from "../api/client";

export default function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const data = await api.dashboardSummary();
        if (!cancelled) setSummary(data);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    }
    load();
    const id = setInterval(load, 5000); // real backend is cheap to poll; keeps counts live
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">RTASA Security Dashboard</h1>
        <p className="mt-1 text-sm text-slate-500">
          Live state of the running RTASA backend. Every number below is read straight from it.
        </p>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-900/60 bg-rose-950/30 p-4 text-sm text-rose-300">
          Could not reach the backend at <code>http://127.0.0.1:8000</code>: {error}. Make sure{" "}
          <code>python cli.py serve</code> is running.
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5">
          <StatCard label="Protected Records" value={String(summary.protected_records)} icon={FileText} />
          <StatCard label="Active Custodians" value={String(summary.active_custodians)} icon={Users} />
          <StatCard
            label="Threshold"
            value={summary.threshold ? `${summary.threshold.k} of ${summary.threshold.n}` : "—"}
            icon={Gauge}
          />
          <StatCard
            label="Pending Requests"
            value={String(summary.pending_requests)}
            tone={summary.pending_requests > 0 ? "warn" : "default"}
            icon={Clock}
          />
          <StatCard
            label="Audit Status"
            value={summary.audit_integrity_ok ? "✓ Verified" : "✗ Problem"}
            tone={summary.audit_integrity_ok ? "good" : "bad"}
            icon={ScrollText}
          />
        </div>
      )}

      <Pipeline />
    </div>
  );
}

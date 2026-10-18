import { Link } from "react-router-dom";
import { ScrollText, ShieldCheck } from "lucide-react";
import { useBackendStatus } from "../hooks/useBackendStatus";

const STATUS_STYLE: Record<string, { dot: string; text: string; label: string }> = {
  checking: { dot: "bg-slate-500 animate-pulse", text: "text-slate-400", label: "Checking backend…" },
  online: { dot: "bg-emerald-500 animate-pulse", text: "text-emerald-300", label: "Backend online" },
  offline: { dot: "bg-rose-500", text: "text-rose-300", label: "Backend offline" },
};

export default function Header() {
  const status = useBackendStatus();
  const s = STATUS_STYLE[status];

  return (
    <header className="flex items-center justify-between border-b border-slate-800 bg-slate-950/80 px-6 py-4">
      <div className="flex items-center gap-3">
        <ShieldCheck className="h-7 w-7 text-violet-400" strokeWidth={1.75} />
        <div>
          <h1 className="text-base font-bold leading-tight tracking-wide text-slate-100">RTASA</h1>
          <p className="text-xs leading-tight text-slate-500">
            Role-Based Threshold-Access Hybrid Encryption and Steganography with Tamper-Evident
            Audit Trails
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <Link
          to="/console/audit"
          className="flex items-center gap-1.5 rounded-full border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-violet-600 hover:text-violet-300"
          title="Every action (role creation, issuance, requests, approvals, recoveries) logged as a signed, hash-chained entry"
        >
          <ScrollText className="h-3.5 w-3.5" /> Audit Trail
        </Link>
        <div
          className={`flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium ${s.text}`}
          title="Reflects whether the FastAPI backend at http://127.0.0.1:8000 answered the last health check"
        >
          <span className={`h-2 w-2 rounded-full ${s.dot}`} />
          {s.label}
        </div>
      </div>
    </header>
  );
}

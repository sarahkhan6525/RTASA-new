import type { LucideIcon } from "lucide-react";

interface Props {
  label: string;
  value: string;
  tone?: "default" | "good" | "warn" | "bad";
  icon?: LucideIcon;
}

const toneClasses: Record<string, string> = {
  default: "text-slate-100",
  good: "text-emerald-400",
  warn: "text-amber-400",
  bad: "text-rose-400",
};

const iconToneClasses: Record<string, string> = {
  default: "text-slate-500",
  good: "text-emerald-500/70",
  warn: "text-amber-500/70",
  bad: "text-rose-500/70",
};

export default function StatCard({ label, value, tone = "default", icon: Icon }: Props) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
      <div className="flex items-center justify-between">
        <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
        {Icon && <Icon className={`h-4 w-4 ${iconToneClasses[tone]}`} strokeWidth={1.75} />}
      </div>
      <div className={`mt-2 text-2xl font-semibold ${toneClasses[tone]}`}>{value}</div>
    </div>
  );
}

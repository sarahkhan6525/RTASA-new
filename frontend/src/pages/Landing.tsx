import { Link } from "react-router-dom";
import { ShieldPlus, Users, KeyRound } from "lucide-react";

const CHOICES = [
  {
    to: "/login/owner",
    icon: ShieldPlus,
    title: "I am an Owner",
    desc: "I want to protect a record.",
  },
  {
    to: "/login/custodian",
    icon: Users,
    title: "I am a Custodian",
    desc: "I hold a share of one or more records and need to review and approve pending access requests.",
  },
  {
    to: "/login/requester",
    icon: KeyRound,
    title: "I am a Requester",
    desc: "I need to request and recover a record I'm entitled to.",
  },
];

export default function Landing() {
  return (
    <div className="mx-auto max-w-3xl pt-16 text-center">
      <h1 className="text-2xl font-semibold text-slate-100">Welcome to RTASA</h1>
      <p className="mx-auto mt-2 max-w-xl text-sm text-slate-500">
        Sign in with your email to continue. Which best describes you for this session?
      </p>

      <div className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-3">
        {CHOICES.map((c) => {
          const Icon = c.icon;
          return (
            <Link
              key={c.to}
              to={c.to}
              className="flex flex-col items-center rounded-2xl border border-slate-800 bg-slate-900/60 p-6 text-left transition hover:border-violet-600 hover:bg-slate-900"
            >
              <Icon className="h-8 w-8 text-violet-400" strokeWidth={1.75} />
              <div className="mt-3 text-sm font-semibold text-slate-100">{c.title}</div>
              <p className="mt-2 text-xs leading-relaxed text-slate-500">{c.desc}</p>
            </Link>
          );
        })}
      </div>
    </div>
  );
}

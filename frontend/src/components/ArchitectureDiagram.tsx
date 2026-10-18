// An auto-playing, looping walk through the RTASA pipeline (Fig. 1:
// "issuance (steps 1-5) and recovery (steps 6-9)") -- purely for
// explanation, not tied to any real action. Advances on its own so it
// can run unattended on a projector while you talk over it.
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  UserRound, Lock, Share2, ShieldCheck, KeyRound, Image as ImageIcon, Database,
  Send, Unlock, RefreshCw, Sigma, LockOpen, Play, Pause,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import Katex from "./Katex";

interface Node {
  id: string;
  title: string;
  eq?: string;
  tex?: string;
  who: string;
  blurb: string;
  icon: LucideIcon;
  color: string; // tailwind color stem, e.g. "violet"
}

const ISSUANCE: Node[] = [
  { id: "owner", title: "Owner (D)", who: "Entity", icon: UserRound, color: "slate",
    blurb: "Authenticates with credential + OTP, then submits a record M under identifier id." },
  { id: "aes", title: "AES-256-GCM encrypt", eq: "eq. 2", tex: "C=\\mathrm{AES\\text{-}GCM}_{k_e}(M;\\,id)", who: "Layer E", icon: Lock, color: "sky",
    blurb: "K sampled uniformly from Z_q, k_e derived via HKDF; the record is encrypted and authenticated." },
  { id: "shamir", title: "Shamir (k,n) split", eq: "eq. 3", tex: "f(x)=K+a_1x+\\cdots+a_{k-1}x^{k-1}", who: "Layer T", icon: Share2, color: "violet",
    blurb: "K is split by a random polynomial; each custodian R_i gets the share y_i = f(x_i)." },
  { id: "feldman", title: "Feldman commitments", eq: "eq. 4", tex: "y_iG=\\sum_{j=0}^{k-1}x_i^{\\,j}C_j", who: "Layer T", icon: ShieldCheck, color: "violet",
    blurb: "C_j = a_jG is published to the log, so any share can later be checked without learning K." },
  { id: "rsa", title: "RSA-OAEP wrap", eq: "eq. 5", tex: "Z_i=\\mathrm{OAEP}_{pk_i}(x_i\\,\\|\\,y_i\\,\\|\\,id)", who: "Layer A", icon: KeyRound, color: "amber",
    blurb: "Cryptographic role-binding and id-binding prevent replay across records (Table III)." },
  { id: "stego", title: "LSB-matching embed", eq: "eq. 6", tex: "G_i=\\mathrm{Embed}(I_i,Z_i;\\kappa_i)", who: "Layer S", icon: ImageIcon, color: "fuchsia",
    blurb: "Z_i is hidden inside an ordinary-looking cover image, invisible without kappa_i." },
  { id: "carrier", title: "Carrier repository", who: "Storage", icon: Database, color: "slate",
    blurb: "G_i is stored among ordinary images; an observer can't tell which, if any, carry a share (G3)." },
];

const RECOVERY: Node[] = [
  { id: "request", title: "Requester (Q) requests", who: "Entity", icon: Send, color: "slate",
    blurb: "Q sends a signed request; a policy check refuses an unentitled Q (Table III)." },
  { id: "extract", title: "Custodian extracts & unwraps", eq: "eq. 8", tex: "(x_i,y_i)=\\mathrm{OAEP}^{-1}_{sk_i}(\\mathrm{Extract}(G_i;\\kappa_i))", who: "Layer S+A", icon: Unlock, color: "fuchsia",
    blurb: "Each approving custodian independently extracts and decrypts its own share." },
  { id: "verify", title: "Feldman re-check", eq: "eq. 4", tex: "y_iG\\stackrel{?}{=}\\sum_{j}x_i^{\\,j}C_j", who: "Layer T", icon: ShieldCheck, color: "violet",
    blurb: "The extracted share is checked against the published commitments before it's trusted." },
  { id: "rewrap", title: "Re-wrap for Q, sign, log", who: "Layer A+L", icon: RefreshCw, color: "amber",
    blurb: "The custodian re-wraps the share under Q's key, signs it, and logs share_approved." },
  { id: "lagrange", title: "Lagrange interpolation", eq: "eq. 9", tex: "K=\\sum_{j\\in A}y_j\\!\\!\\prod_{m\\in A,\\,m\\ne j}\\!\\!\\frac{x_m}{x_m-x_j}\\!\\!\\mod q", who: "Layer T", icon: Sigma, color: "violet",
    blurb: "With |A| >= k valid shares, Q reconstructs K by interpolating at x = 0." },
  { id: "decrypt", title: "AES-256-GCM decrypt", eq: "eq. 2⁻¹", tex: "M=\\mathrm{AES\\text{-}GCM}^{-1}_{k_e}(C;\\,id)", who: "Layer E", icon: LockOpen, color: "sky",
    blurb: "Q derives k_e and decrypts C; the GCM tag confirms integrity, logged as record_recovered." },
];

const COLOR_RING: Record<string, string> = {
  slate: "ring-slate-400/60 border-slate-400 text-slate-200 shadow-slate-500/30",
  sky: "ring-sky-400/70 border-sky-400 text-sky-200 shadow-sky-500/40",
  violet: "ring-violet-400/70 border-violet-400 text-violet-200 shadow-violet-500/40",
  amber: "ring-amber-400/70 border-amber-400 text-amber-200 shadow-amber-500/40",
  fuchsia: "ring-fuchsia-400/70 border-fuchsia-400 text-fuchsia-200 shadow-fuchsia-500/40",
};
const COLOR_BG: Record<string, string> = {
  slate: "bg-slate-500/15",
  sky: "bg-sky-500/15",
  violet: "bg-violet-500/15",
  amber: "bg-amber-500/15",
  fuchsia: "bg-fuchsia-500/15",
};
const COLOR_DOT: Record<string, string> = {
  slate: "bg-slate-400", sky: "bg-sky-400", violet: "bg-violet-400", amber: "bg-amber-400", fuchsia: "bg-fuchsia-400",
};

function NodeChip({ n, active, done, onClick }: { n: Node; active: boolean; done: boolean; onClick: () => void }) {
  const Icon = n.icon;
  return (
    <button onClick={onClick} className="group flex shrink-0 flex-col items-center gap-1.5" style={{ width: 92 }}>
      <motion.div
        animate={{
          scale: active ? 1.18 : 1,
          opacity: active ? 1 : done ? 0.9 : 0.55,
        }}
        transition={{ type: "spring", stiffness: 300, damping: 18 }}
        className={`relative flex h-12 w-12 items-center justify-center rounded-full border-2 bg-slate-950 ${
          active ? `${COLOR_RING[n.color]} shadow-lg` : done ? "border-slate-600 text-slate-300" : "border-slate-800 text-slate-600"
        }`}
      >
        {active && (
          <motion.span
            className={`absolute inset-0 rounded-full ${COLOR_BG[n.color]}`}
            animate={{ scale: [1, 1.6], opacity: [0.7, 0] }}
            transition={{ duration: 1.3, repeat: Infinity, ease: "easeOut" }}
          />
        )}
        <Icon className="h-5 w-5" strokeWidth={1.75} />
      </motion.div>
      <span className={`text-center text-[10px] leading-tight ${active ? "font-semibold text-slate-100" : "text-slate-500"}`}>
        {n.title}
      </span>
      {n.eq && (
        <span className={`rounded px-1 text-[9px] ${active ? "bg-slate-800 text-slate-300" : "text-slate-700"}`}>{n.eq}</span>
      )}
    </button>
  );
}

function Connector({ litFrom, litTo, color }: { litFrom: boolean; litTo: boolean; color: string }) {
  const lit = litFrom && litTo;
  return (
    <div className="relative top-[-20px] h-[2px] w-6 shrink-0 overflow-hidden rounded-full bg-slate-800 sm:w-10">
      <motion.span
        className={`absolute top-0 h-full w-3 rounded-full ${lit ? COLOR_DOT[color] : "bg-slate-600"}`}
        animate={{ left: ["-20%", "110%"] }}
        transition={{ duration: 1.1, repeat: Infinity, ease: "linear" }}
      />
    </div>
  );
}

function Row({ nodes, activeIndex, onPick }: { nodes: Node[]; activeIndex: number; onPick: (i: number) => void }) {
  return (
    <div className="flex items-start overflow-x-auto pb-2 pt-1">
      {nodes.map((n, i) => (
        <div key={n.id} className="flex items-start">
          <NodeChip n={n} active={i === activeIndex} done={i < activeIndex} onClick={() => onPick(i)} />
          {i < nodes.length - 1 && (
            <Connector litFrom={i <= activeIndex} litTo={i + 1 <= activeIndex} color={nodes[i + 1].color} />
          )}
        </div>
      ))}
    </div>
  );
}

const TOTAL_NODES = ISSUANCE.length + RECOVERY.length;

export default function ArchitectureDiagram() {
  // A single flat step counter (0..TOTAL_NODES-1) drives both the issuance
  // and recovery rows -- phase/index are *derived* from it, never stored
  // separately. Two coupled state variables updated from inside each
  // other's setState updater (the previous version's bug: setPhase called
  // inside setIndex's updater) is impure and gets double-invoked by
  // React 18 StrictMode in dev, which silently toggled the phase forward
  // then right back again every time it tried to leave "issuance" -- the
  // diagram never reached recovery. A single pure counter can't do that.
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(true);

  useEffect(() => {
    if (!playing) return;
    const id = setInterval(() => {
      setStep((prev) => (prev + 1) % TOTAL_NODES);
    }, 1800);
    return () => clearInterval(id);
  }, [playing]);

  const phase: "issuance" | "recovery" = step < ISSUANCE.length ? "issuance" : "recovery";
  const index = phase === "issuance" ? step : step - ISSUANCE.length;

  function jumpTo(which: "issuance" | "recovery", i: number) {
    setPlaying(false);
    setStep(which === "issuance" ? i : ISSUANCE.length + i);
  }

  const current = (phase === "issuance" ? ISSUANCE : RECOVERY)[index];
  const CurrentIcon = current.icon;
  const totalSteps = TOTAL_NODES;
  const progressPct = ((step + 1) / totalSteps) * 100;

  return (
    <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-950/80 p-6">
      {/* ambient glow */}
      <motion.div
        className="pointer-events-none absolute -left-24 -top-24 h-72 w-72 rounded-full bg-violet-600/20 blur-3xl"
        animate={{ opacity: [0.5, 0.9, 0.5] }}
        transition={{ duration: 6, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className="pointer-events-none absolute -bottom-24 -right-16 h-72 w-72 rounded-full bg-sky-600/20 blur-3xl"
        animate={{ opacity: [0.9, 0.5, 0.9] }}
        transition={{ duration: 7, repeat: Infinity, ease: "easeInOut" }}
      />

      <div className="relative">
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
              Fig. 1: RTASA workflow, playing automatically
            </h2>
            <p className="mt-0.5 text-xs text-slate-500">Issuance (steps 1-5), then recovery (steps 6-9). Click any step to jump there.</p>
          </div>
          <button
            onClick={() => setPlaying(!playing)}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-300 hover:border-violet-600 hover:text-violet-300"
          >
            {playing ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
            {playing ? "Pause" : "Play"}
          </button>
        </div>

        {/* progress rail */}
        <div className="mb-5 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
          <motion.div
            className="h-full rounded-full bg-gradient-to-r from-sky-400 via-violet-400 to-fuchsia-400"
            animate={{ width: `${progressPct}%` }}
            transition={{ duration: 0.4 }}
          />
        </div>

        {/* "now playing" headline card */}
        <AnimatePresence mode="wait">
          <motion.div
            key={`${phase}-${index}`}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.3 }}
            className={`mb-5 flex items-start gap-4 rounded-xl border p-4 ${COLOR_RING[current.color]} ${COLOR_BG[current.color]}`}
          >
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-slate-950/60">
              <CurrentIcon className="h-5 w-5" strokeWidth={1.75} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wide opacity-80">{current.who}</span>
                <span className="text-sm font-semibold text-slate-100">{current.title}</span>
                {current.eq && <span className="rounded bg-slate-950/60 px-1.5 py-0.5 text-[10px] text-slate-300">{current.eq}</span>}
              </div>
              <p className="mt-1 text-xs text-slate-300">{current.blurb}</p>
              {current.tex && (
                <div className="mt-2 overflow-x-auto rounded-lg bg-slate-950/60 px-3 py-2 text-slate-100">
                  <Katex tex={current.tex} />
                </div>
              )}
            </div>
          </motion.div>
        </AnimatePresence>

        <div className="space-y-5">
          <div>
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
              Issuance: owner protects a record
            </div>
            <Row nodes={ISSUANCE} activeIndex={phase === "issuance" ? index : ISSUANCE.length} onPick={(i) => jumpTo("issuance", i)} />
          </div>
          <div>
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
              Recovery: custodians approve, requester reconstructs
            </div>
            <Row nodes={RECOVERY} activeIndex={phase === "recovery" ? index : -1} onPick={(i) => jumpTo("recovery", i)} />
          </div>
        </div>
      </div>
    </div>
  );
}

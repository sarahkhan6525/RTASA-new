// A small, honest "it's not just a button click" visual: walks through a
// named sequence of real cryptographic sub-steps in the exact order the
// backend actually performs them for one action (one issuance call, one
// approval call, or one recovery call). The backend does all of this
// synchronously inside a single HTTP request -- there is no granular
// progress feed to stream -- so this component plays the sequence back as
// a timed reveal while the real request is in flight, then snaps straight
// to "done" the moment the real response lands (even if the animation
// hasn't finished walking through every step yet). Nothing here is
// fabricated data: the detail text and equations under each step are
// drawn from the paper's own equations/sections (typeset with KaTeX, not
// plain-text approximations), and any live values passed in (an OTP, a
// Feldman commitment, a byte count) are the real ones from the actual API
// response, not placeholders.
import { useEffect, useRef, useState } from "react";
import { Check, Circle } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  Lock, LockOpen, Share2, ShieldCheck, KeyRound, Image as ImageIcon,
  Database, ScrollText, Unlock, RefreshCw, Sigma,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import Katex from "./Katex";

export interface PipelineStep {
  id: string;
  label: string;
  eq?: string; // which equation / section of the paper this step realizes
  tex?: string; // the actual equation, typeset with KaTeX when present
  detail: string;
  icon?: LucideIcon;
  color?: "sky" | "violet" | "amber" | "fuchsia" | "emerald" | "slate";
}

type StepStatus = "pending" | "active" | "done";

interface LiveStepsProps {
  steps: PipelineStep[];
  running: boolean; // true while the real API call is in flight
  settled: boolean; // true once the real API call has resolved (success or error)
  stepMs?: number; // how long each step's animated "active" phase lasts
  liveValues?: Record<string, string>; // step id -> a real value to show once done
}

const RING: Record<string, string> = {
  sky: "border-sky-400 ring-sky-400/60 text-sky-200",
  violet: "border-violet-400 ring-violet-400/60 text-violet-200",
  amber: "border-amber-400 ring-amber-400/60 text-amber-200",
  fuchsia: "border-fuchsia-400 ring-fuchsia-400/60 text-fuchsia-200",
  emerald: "border-emerald-400 ring-emerald-400/60 text-emerald-200",
  slate: "border-slate-400 ring-slate-400/60 text-slate-200",
};
const GLOW: Record<string, string> = {
  sky: "bg-sky-500/20", violet: "bg-violet-500/20", amber: "bg-amber-500/20",
  fuchsia: "bg-fuchsia-500/20", emerald: "bg-emerald-500/20", slate: "bg-slate-500/20",
};

export default function LiveSteps({ steps, running, settled, stepMs = 550, liveValues }: LiveStepsProps) {
  const [doneCount, setDoneCount] = useState(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!running) {
      setDoneCount(0);
      return;
    }
    // Walk through the steps on a fixed cadence while the real call is
    // outstanding. Leaves the very last step in "active" (never auto-marks
    // it done) so the UI never claims completion before the real response
    // has actually arrived.
    function tick(n: number) {
      timerRef.current = setTimeout(() => {
        setDoneCount((d) => Math.max(d, n));
        if (n < steps.length - 1) tick(n + 1);
      }, stepMs);
    }
    setDoneCount(0);
    tick(0);
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running, steps.length, stepMs]);

  useEffect(() => {
    if (settled) setDoneCount(steps.length); // real response is in -- snap everything to done
  }, [settled, steps.length]);

  if (!running && !settled) return null;

  function statusFor(i: number): StepStatus {
    if (i < doneCount) return "done";
    if (i === doneCount && (running || settled)) return "active";
    return "pending";
  }

  const activeIdx = Math.min(doneCount, steps.length - 1);
  const progressPct = (Math.min(doneCount, steps.length) / steps.length) * 100;

  return (
    <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-slate-950/70 p-3">
      <motion.div
        className="pointer-events-none absolute -right-10 -top-10 h-40 w-40 rounded-full bg-violet-600/10 blur-2xl"
        animate={{ opacity: [0.5, 1, 0.5] }}
        transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
      />

      <div className="relative mb-3 h-1 w-full overflow-hidden rounded-full bg-slate-800">
        <motion.div
          className="h-full rounded-full bg-gradient-to-r from-sky-400 via-violet-400 to-fuchsia-400"
          animate={{ width: `${progressPct}%` }}
          transition={{ duration: 0.35 }}
        />
      </div>

      <div className="relative space-y-1">
        {steps.map((s, i) => {
          const status = statusFor(i);
          const value = liveValues?.[s.id];
          const Icon = s.icon ?? Circle;
          const color = s.color ?? "violet";
          return (
            <motion.div
              key={s.id}
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: status === "pending" ? 0.45 : 1, x: 0 }}
              className="flex items-start gap-2.5 rounded-lg px-1 py-1.5"
            >
              <span className="relative mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border bg-slate-950">
                {status === "done" && (
                  <span className="flex h-full w-full items-center justify-center rounded-full border border-emerald-500 bg-emerald-500/10 text-emerald-400">
                    <Check className="h-3.5 w-3.5" />
                  </span>
                )}
                {status === "active" && (
                  <span className={`relative flex h-full w-full items-center justify-center rounded-full border ${RING[color]}`}>
                    <motion.span
                      className={`absolute inset-0 rounded-full ${GLOW[color]}`}
                      animate={{ scale: [1, 1.7], opacity: [0.8, 0] }}
                      transition={{ duration: 1.1, repeat: Infinity, ease: "easeOut" }}
                    />
                    <Icon className="h-3.5 w-3.5" strokeWidth={1.75} />
                  </span>
                )}
                {status === "pending" && (
                  <span className="flex h-full w-full items-center justify-center rounded-full border border-slate-800 text-slate-700">
                    <Icon className="h-3.5 w-3.5" strokeWidth={1.75} />
                  </span>
                )}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`text-xs font-medium ${
                      status === "pending" ? "text-slate-500" : status === "active" ? "text-violet-300" : "text-slate-200"
                    }`}
                  >
                    {s.label}
                  </span>
                </div>
                <AnimatePresence>
                  {status !== "pending" && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      className="overflow-hidden"
                    >
                      <p className="text-[11px] text-slate-500">
                        {s.detail}
                        {status === "done" && value && (
                          <span className="ml-1 break-all rounded bg-slate-950 px-1 py-0.5 font-mono text-emerald-400">
                            {value}
                          </span>
                        )}
                      </p>
                      {s.tex && (
                        <div className="mt-1.5 overflow-x-auto rounded-lg bg-slate-900/80 px-2.5 py-1.5 text-sm text-slate-100">
                          <Katex tex={s.tex} />
                        </div>
                      )}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
          );
        })}
      </div>

      <p className="relative mt-2 text-right text-[10px] text-slate-600">
        step {Math.min(activeIdx + 1, steps.length)} of {steps.length}
      </p>
    </div>
  );
}

// -- Stage definitions, one set per real backend operation ------------------
// Ordering and equation references are taken directly from Sec. IV of the
// paper; this is the same sequence rtasa/issuance.py and rtasa/recovery.py
// actually execute, just narrated -- icons/colors match the Architecture
// tab's diagram so the same step always looks the same everywhere.

export const ISSUANCE_STEPS: PipelineStep[] = [
  { id: "aes", label: "AES-256-GCM encrypt", icon: Lock, color: "sky",
    tex: "C=\\mathrm{AES\\text{-}GCM}_{k_e}(M;\\,id)",
    detail: "Your record is locked with a brand new secret key. If anyone tries to tamper with the locked version later, that tampering will be caught." },
  { id: "shamir", label: "Shamir (k,n) split", icon: Share2, color: "violet",
    tex: "f(x)=K+a_1x+\\cdots+a_{k-1}x^{k-1}\\!\\!\\mod q",
    detail: "The secret key that unlocks your record is broken into pieces and given to your custodians. Only when enough of them come together can the key be rebuilt; having just a few pieces reveals nothing on their own." },
  { id: "feldman", label: "Feldman commitments published", icon: ShieldCheck, color: "violet",
    tex: "y_iG=\\sum_{j=0}^{k-1}x_i^{\\,j}C_j",
    detail: "A way to check that each piece is genuine is recorded, so if anyone tries to use a fake or altered piece later, it can be caught." },
  { id: "rsa", label: "Role-bound RSA-OAEP wrap", icon: KeyRound, color: "amber",
    tex: "Z_i=\\mathrm{OAEP}_{pk_i}(x_i\\,\\|\\,y_i\\,\\|\\,id)",
    detail: "Each custodian's piece is locked again, this time so that only that specific custodian can ever open it. Nobody else, not even another custodian, can use someone else's piece." },
  { id: "stego", label: "LSB-matching steganography embed", icon: ImageIcon, color: "fuchsia",
    tex: "G_i=\\mathrm{Embed}(I_i,Z_i;\\kappa_i)",
    detail: "Each locked piece is then hidden inside an ordinary-looking photo, so it's invisible to anyone just looking at the image." },
  { id: "carrier", label: "Carrier images stored", icon: Database, color: "slate",
    detail: "Those photos, with the hidden pieces inside them, are what actually gets saved. They look just like normal photos to anyone who doesn't have the key to extract what's hidden." },
  { id: "audit", label: "Audit log entries signed & appended", icon: ScrollText, color: "emerald",
    detail: "Every single step above is written down in a tamper-evident log, so there's a permanent, verifiable record of exactly what happened." },
];

export const REQUEST_STEPS: PipelineStep[] = [
  { id: "auth", label: "Authenticate requester (passphrase + OTP)", icon: KeyRound, color: "amber",
    detail: "The requester's identity is checked first, before anything about the record is touched." },
  { id: "policy", label: "Entitlement / policy check", icon: ShieldCheck, color: "violet",
    detail: "The system checks whether this person is actually allowed to request this record. Someone who isn't allowed gets refused, and that refusal is written down too, not just hidden from view." },
  { id: "log", label: "Sign & log recovery_requested", icon: ScrollText, color: "emerald",
    detail: "This request is written into the log and signed. A refusal gets logged in exactly the same way a successful request does." },
];

export const APPROVAL_STEPS: PipelineStep[] = [
  { id: "extract", label: "Extract hidden share from carrier image", icon: ImageIcon, color: "fuchsia",
    detail: "The custodian's own photo is opened back up and the hidden piece is carefully pulled out of it." },
  { id: "unwrap", label: "Unwrap with custodian's private key", icon: Unlock, color: "amber",
    tex: "(x_i,y_i)=\\mathrm{OAEP}^{-1}_{sk_i}(\\mathrm{Extract}(G_i;\\kappa_i))",
    detail: "The piece is unlocked using only this custodian's own private key. No one else, not even another custodian, could do this step." },
  { id: "feldman-check", label: "Verify against Feldman commitment", icon: ShieldCheck, color: "violet",
    tex: "y_iG\\stackrel{?}{=}\\sum_{j}x_i^{\\,j}C_j",
    detail: "The piece is checked against the record that was logged earlier, to make sure it's genuine and hasn't been altered. A fake or corrupted piece would be caught right here." },
  { id: "rewrap", label: "Re-wrap for the requester", icon: RefreshCw, color: "amber",
    detail: "Once it checks out, the piece is locked again, this time so that only the requester can open it. The custodian never hands over the piece itself in the open." },
  { id: "sign", label: "Sign & log this approval", icon: ScrollText, color: "emerald",
    detail: "This approval is written down and signed, adding a new, permanent entry to the log." },
];

export const RECOVERY_STEPS: PipelineStep[] = [
  { id: "unwrap-all", label: "Unwrap each approved share", icon: Unlock, color: "fuchsia",
    detail: "The requester uses their own private key to unlock every piece the custodians sent over." },
  { id: "feldman-recheck", label: "Re-verify each share", icon: ShieldCheck, color: "violet",
    tex: "y_iG\\stackrel{?}{=}\\sum_{j}x_i^{\\,j}C_j",
    detail: "Each piece is checked one more time to make sure it's genuine before it's trusted." },
  { id: "interpolate", label: "Lagrange interpolation", icon: Sigma, color: "violet",
    tex: "K=\\sum_{j\\in A}y_j\\!\\!\\prod_{m\\in A,\\,m\\ne j}\\!\\!\\frac{x_m}{x_m-x_j}\\!\\!\\mod q",
    detail: "Once enough genuine pieces are collected, they're combined to rebuild the original secret key. Having fewer pieces than required reveals nothing about the key at all." },
  { id: "decrypt", label: "AES-256-GCM decrypt", icon: LockOpen, color: "sky",
    tex: "M=\\mathrm{AES\\text{-}GCM}^{-1}_{k_e}(C;\\,id)",
    detail: "That rebuilt key is used to unlock the record, and a built-in check confirms nothing was tampered with along the way." },
  { id: "checkpoint", label: "Audit entry + custodian checkpoint", icon: ScrollText, color: "emerald",
    detail: "This recovery is written into the log, and all the custodians add their signatures to confirm the log hasn't been changed." },
];

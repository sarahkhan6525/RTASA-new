import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

interface Stage {
  id: string;
  label: string;
  eq: string;
  blurb: string;
}

const STAGES: Stage[] = [
  {
    id: "record",
    label: "Sensitive Record",
    eq: "—",
    blurb: "The plaintext the owner wants to protect. Lives only in memory for the moment it's encrypted; never written to disk or logged.",
  },
  {
    id: "aes",
    label: "AES-256-GCM",
    eq: "eq. 2",
    blurb: "A fresh 256-bit key (derived via HKDF) encrypts the record and produces an authentication tag that detects any later tampering with the ciphertext.",
  },
  {
    id: "shamir",
    label: "Shamir (k,n) + Feldman",
    eq: "eq. 3, 4, 9",
    blurb: "The encryption key is split into n shares with a (k,n) threshold: any k rebuild it, any fewer reveal nothing. Feldman commitments let each share be verified as genuine before it's trusted.",
  },
  {
    id: "rsa",
    label: "Role-bound RSA-OAEP",
    eq: "eq. 5",
    blurb: "Each share is wrapped under its specific custodian's RSA public key, so only that role's private key can ever unwrap that particular share.",
  },
  {
    id: "stego",
    label: "LSB-matching Steganography",
    eq: "eq. 6",
    blurb: "Each wrapped share is hidden inside an ordinary-looking cover image by lightly adjusting pixel values: invisible to the eye, and indistinguishable from a plain photo without the extraction key.",
  },
  {
    id: "carriers",
    label: "Carrier Repository",
    eq: "Sec. IV-B",
    blurb: "The carrier images (one per custodian) are what actually gets stored. An observer of the repository cannot tell which images, if any, are carrying a hidden share.",
  },
  {
    id: "audit",
    label: "Tamper-Evident Audit Log",
    eq: "eq. 7, Sec. IV-C",
    blurb: "Every action above is recorded as a signed, hash-chained entry, periodically witnessed by custodian checkpoints, so a rewritten or truncated log is detectable, not just \"trust us.\"",
  },
];

export default function Pipeline() {
  const [openId, setOpenId] = useState<string | null>(null);
  const open = STAGES.find((s) => s.id === openId) ?? null;

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-400">
        RTASA pipeline: click a stage
      </h2>
      <div className="flex flex-wrap items-center gap-2">
        {STAGES.map((s, i) => (
          <div key={s.id} className="flex items-center gap-2">
            <button
              onClick={() => setOpenId(openId === s.id ? null : s.id)}
              className={`rounded-xl border px-4 py-3 text-left text-sm font-medium transition-colors ${
                openId === s.id
                  ? "border-violet-500 bg-violet-500/10 text-violet-300"
                  : "border-slate-700 bg-slate-800/60 text-slate-200 hover:border-slate-500"
              }`}
            >
              {s.label}
            </button>
            {i < STAGES.length - 1 && <span className="text-slate-600">→</span>}
          </div>
        ))}
      </div>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="mt-4 rounded-xl border border-violet-900/50 bg-violet-950/20 p-4 text-sm text-slate-200">
              <div className="mb-1 flex items-center gap-2">
                <span className="font-semibold text-violet-300">{open.label}</span>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-400">
                  {open.eq}
                </span>
              </div>
              <p className="text-slate-300">{open.blurb}</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

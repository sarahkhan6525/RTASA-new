import { Network, ShieldCheck } from "lucide-react";
import ArchitectureDiagram from "../components/ArchitectureDiagram";
import Katex from "../components/Katex";

const GOALS = [
  { id: "G1", title: "Confidentiality without k custodians", body: "Fewer than k shares are information-theoretically independent of K (Shamir's perfect secrecy); the rest are OAEP-protected." },
  { id: "G2", title: "Shares usable only by their role", body: "Only sk_i opens Z_i -- role-bound RSA-OAEP wrapping (eq. 5) makes a share useless to anyone but its intended custodian." },
  { id: "G3", title: "An observer can't tell which images carry a share", body: "LSB-matching steganography (eq. 6); measured directly in Sec. V-D via RS/SPA/SPAM steganalysis, not just asserted." },
  { id: "G4", title: "No event can be altered or suppressed undetected", body: "Hash-chained, ECDSA-signed audit log with custodian checkpoints (Sec. IV-C) -- altering it needs a forged signature or a disagreement with a held checkpoint." },
];

const ENTITIES = [
  { role: "Owner (D)", desc: "The data owner. Submits a record M with identifier id and acts as the Shamir dealer." },
  { role: "Custodian roles (R_i)", desc: `Each of n custodian roles holds RSA and ECDSA signing key pairs in a role key store "that only authenticated members can use."` },
  { role: "Requester (Q)", desc: "An entitled user who may request recovery -- entitlement is enforced by a policy check, not just UI (Table III: unentitled requesters are refused)." },
  { role: "Carrier repository & log host", desc: "Both are explicitly untrusted in the threat model: the adversary may read and modify all storage and control the log host." },
];

const EQUATIONS: { n: string; tex: string; meaning: string }[] = [
  { n: "eq. 2", tex: "C=\\mathrm{AES\\text{-}GCM}_{k_e}(M;\\,id)", meaning: "Encrypt the record, binding id as associated data so a GCM-authenticated ciphertext can't be replayed under a different id." },
  { n: "eq. 3", tex: "f(x)=K+a_1x+\\cdots+a_{k-1}x^{k-1}\\!\\!\\mod q", meaning: "Shamir's (k,n) polynomial -- role R_i's share is y_i = f(x_i) at a fixed public point x_i ≠ 0." },
  { n: "eq. 4", tex: "y_iG=\\sum_{j=0}^{k-1}x_i^{\\,j}C_j,\\quad C_j=a_jG", meaning: "Feldman commitments: anyone holding a share can check it against the published C_j's without learning K." },
  { n: "eq. 5", tex: "Z_i=\\mathrm{OAEP}_{pk_i}(x_i\\,\\|\\,y_i\\,\\|\\,id)", meaning: "RSA-OAEP wraps the share under the custodian's own public key, binding both the role and the record id." },
  { n: "eq. 6", tex: "G_i=\\mathrm{Embed}(I_i,Z_i;\\kappa_i)", meaning: "LSB-matching steganography hides Z_i inside cover image I_i at positions chosen by the per-role key kappa_i." },
  { n: "eq. 8", tex: "(x_i,y_i)=\\mathrm{OAEP}^{-1}_{sk_i}(\\mathrm{Extract}(G_i;\\kappa_i))", meaning: "At recovery, a custodian extracts and unwraps its own share -- the inverse of eq. 5-6." },
  { n: "eq. 9", tex: "K=\\sum_{j\\in A}y_j\\!\\!\\prod_{m\\in A,\\,m\\ne j}\\!\\!\\frac{x_m}{x_m-x_j}\\!\\!\\mod q", meaning: "Lagrange interpolation at x = 0: with |A| >= k verified shares, the requester reconstructs K." },
  { n: "eq. 2⁻¹", tex: "M=\\mathrm{AES\\text{-}GCM}^{-1}_{k_e}(C;\\,id)", meaning: "The final recovery step -- the inverse of eq. 2. The reconstructed K re-derives k_e, and the GCM tag confirms C wasn't tampered with." },
];

export default function Architecture() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-semibold text-slate-100">
          <Network className="h-5 w-5 text-violet-400" /> RTASA Architecture
        </h1>
        <p className="mt-1 text-sm text-slate-500">
          Role-Based Threshold-Access Hybrid Encryption and Steganography with Tamper-Evident Audit Trails --
          five layers (E / A / T / S / L), composed exactly as Sec. IV describes.
        </p>
      </div>

      <ArchitectureDiagram />

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
          <ShieldCheck className="h-4 w-4" /> Threat model &amp; design goals (Sec. IV-A)
        </h2>
        <p className="mb-4 text-xs text-slate-500">
          "The adversary may read and modify all storage, control the log host, observe the network, and corrupt
          up to k − 1 roles; it cannot corrupt k roles or break AES-GCM, RSA-OAEP, ECDSA, or SHA-256."
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          {GOALS.map((g) => (
            <div key={g.id} className="rounded-xl border border-slate-800 bg-slate-950/50 p-3">
              <div className="mb-1 flex items-center gap-2">
                <span className="rounded bg-violet-500/10 px-1.5 py-0.5 text-xs font-bold text-violet-300">{g.id}</span>
                <span className="text-sm font-medium text-slate-200">{g.title}</span>
              </div>
              <p className="text-xs text-slate-500">{g.body}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-400">Entities</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {ENTITIES.map((e) => (
            <div key={e.role} className="rounded-xl border border-slate-800 bg-slate-950/50 p-3">
              <div className="mb-1 text-sm font-medium text-slate-200">{e.role}</div>
              <p className="text-xs text-slate-500">{e.desc}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-400">
          The equations, in one place
        </h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {EQUATIONS.map((e) => (
            <div key={e.n} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <div className="mb-2 flex items-center justify-between">
                <span className="rounded bg-violet-500/10 px-2 py-0.5 text-[11px] font-semibold text-violet-300">{e.n}</span>
              </div>
              <div className="overflow-x-auto py-1 text-center text-base text-slate-100">
                <Katex tex={e.tex} display />
              </div>
              <p className="mt-2 text-xs text-slate-500">{e.meaning}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

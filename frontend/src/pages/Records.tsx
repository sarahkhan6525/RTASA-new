// A real list of every protected record the backend currently holds
// (GET /records) -- not a mockup. Expanding a record shows its real
// custodian carrier images (the ones steganography actually embedded a
// share into) and the slice of the real audit trail that belongs to it.
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FileText, ChevronDown, ChevronRight, Image as ImageIcon, Users, KeyRound } from "lucide-react";
import { api, type RecordOut, type RoleOut } from "../api/client";
import AuditFeed from "../components/AuditFeed";

export default function Records() {
  const [records, setRecords] = useState<RecordOut[]>([]);
  const [roles, setRoles] = useState<RoleOut[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [recs, rls] = await Promise.all([api.listRecords(), api.listRoles()]);
        if (!cancelled) {
          setRecords(recs);
          setRoles(rls);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    }
    load();
    const id = setInterval(load, 6000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const nameOf = (roleId: string) => roles.find((r) => r.role_id === roleId)?.display_name ?? roleId;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-semibold text-slate-100">
          <FileText className="h-5 w-5 text-violet-400" /> Records
        </h1>
        <p className="mt-1 text-sm text-slate-500">
          Every record currently protected by the running backend, straight from <code>GET /records</code>. Expand
          one to see its real carrier images and the slice of the audit trail that belongs to it.
        </p>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-900/60 bg-rose-950/30 p-4 text-sm text-rose-300">{error}</div>
      )}

      {records.length === 0 && !error && (
        <div className="rounded-2xl border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">
          No records protected yet. Issue one from the Owner Portal to see it here.
        </div>
      )}

      <div className="space-y-3">
        {records.map((r) => {
          const isOpen = openId === r.record_id;
          return (
            <div key={r.record_id} className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/60">
              <button
                onClick={() => setOpenId(isOpen ? null : r.record_id)}
                className="flex w-full items-center gap-3 px-5 py-4 text-left"
              >
                {isOpen ? (
                  <ChevronDown className="h-4 w-4 shrink-0 text-slate-500" />
                ) : (
                  <ChevronRight className="h-4 w-4 shrink-0 text-slate-500" />
                )}
                <div className="flex-1">
                  <div className="font-medium text-slate-200">{r.record_id}</div>
                  <div className="mt-0.5 text-xs text-slate-500">
                    owned by {r.owner_role_id ? nameOf(r.owner_role_id) : "unknown"}
                  </div>
                </div>
                <span className="rounded-full border border-violet-800 bg-violet-950/40 px-2.5 py-1 text-xs font-semibold text-violet-300">
                  {r.threshold}-of-{r.n} threshold
                </span>
              </button>

              <AnimatePresence>
                {isOpen && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="overflow-hidden"
                  >
                    <div className="space-y-4 border-t border-slate-800 px-5 py-4">
                      <div>
                        <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">
                          <Users className="h-3.5 w-3.5" /> Custodians &amp; their carrier images
                        </h3>
                        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4">
                          {r.custodian_role_ids.map((cid) => (
                            <div key={cid} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2 text-center">
                              <img
                                src={api.carrierUrl(r.record_id, cid)}
                                alt={`carrier image for ${cid}`}
                                className="mx-auto mb-1.5 h-20 w-full rounded object-cover"
                              />
                              <div className="flex items-center justify-center gap-1 truncate text-[11px] text-slate-400">
                                <ImageIcon className="h-3 w-3 shrink-0" /> {nameOf(cid)}
                              </div>
                            </div>
                          ))}
                        </div>
                        <p className="mt-2 text-[11px] text-slate-600">
                          Each image above is a real, stored carrier: it genuinely has that custodian's RSA-OAEP-
                          wrapped Shamir share hidden in its pixels (eq. 5-6). There is nothing visibly different
                          between a carrier and an ordinary photo.
                        </p>
                      </div>

                      <div>
                        <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">
                          <KeyRound className="h-3.5 w-3.5" /> Entitled requesters
                        </h3>
                        {r.entitled_requesters.length === 0 ? (
                          <p className="text-xs text-slate-500">
                            Open policy: any authenticated requester may request recovery of this record.
                          </p>
                        ) : (
                          <div className="flex flex-wrap gap-1.5">
                            {r.entitled_requesters.map((rid) => (
                              <span key={rid} className="rounded-full border border-slate-700 bg-slate-800/60 px-2 py-0.5 text-xs text-slate-300">
                                {nameOf(rid)}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>

                      <AuditFeed title="Audit trail for this record" compact filterRecordId={r.record_id} limit={10} />
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </div>
  );
}

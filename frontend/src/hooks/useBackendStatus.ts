import { useEffect, useState } from "react";
import { api } from "../api/client";

export type BackendStatus = "checking" | "online" | "offline";

// Shared by the header pill (and anything else that wants to know at a
// glance whether the real backend is reachable) -- reuses the same cheap
// /dashboard/summary call the Dashboard page already polls, so this adds
// no new endpoint and no real load.
export function useBackendStatus(intervalMs = 5000): BackendStatus {
  const [status, setStatus] = useState<BackendStatus>("checking");

  useEffect(() => {
    let cancelled = false;
    async function check() {
      try {
        await api.dashboardSummary();
        if (!cancelled) setStatus("online");
      } catch {
        if (!cancelled) setStatus("offline");
      }
    }
    check();
    const id = setInterval(check, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [intervalMs]);

  return status;
}

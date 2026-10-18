import { Navigate } from "react-router-dom";
import { getSession, type PortalKind } from "../lib/session";

export default function RequireSession({ kind, children }: { kind: PortalKind; children: React.ReactNode }) {
  const session = getSession(kind);
  if (!session) {
    return <Navigate to={`/login/${kind}`} replace />;
  }
  return <>{children}</>;
}

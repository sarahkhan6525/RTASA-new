// Holds the signed-in portal session (Owner / Custodian / Requester) in
// sessionStorage -- cleared when the tab closes, unlike the demo-credential
// convenience store in credStore.ts. This is a real session token issued
// by POST /auth/verify after passphrase + emailed OTP both check out.

export type PortalKind = "owner" | "custodian" | "requester";

export interface PortalSession {
  token: string;
  role_id: string;
  display_name: string;
  is_custodian: boolean;
  kind: PortalKind;
}

const KEY = "rtasa_portal_session_v1";

export function saveSession(session: PortalSession) {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(session));
  } catch {
    /* ignore -- session just won't survive a refresh */
  }
}

export function getSession(kind?: PortalKind): PortalSession | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    if (!raw) return null;
    const session = JSON.parse(raw) as PortalSession;
    if (kind && session.kind !== kind) return null;
    return session;
  } catch {
    return null;
  }
}

export function clearSession() {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}

// Thin fetch wrapper around the real RTASA FastAPI backend. Every function
// here hits a real endpoint -- nothing in this file returns made-up data.

const BASE = "http://127.0.0.1:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: init?.body ? { "Content-Type": "application/json", ...init.headers } : init?.headers,
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = body.detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export interface DashboardSummary {
  protected_records: number;
  active_custodians: number;
  threshold: { k: number; n: number } | null;
  pending_requests: number;
  audit_integrity_ok: boolean;
  audit_problems: string[];
  audit_entries: number;
}

export interface RoleOut {
  role_id: string;
  display_name: string;
  email?: string | null;
  is_custodian: boolean;
  evaluation_point: number | null;
}

export interface RecordOut {
  record_id: string;
  owner_role_id?: string;
  threshold: number;
  n: number;
  custodian_role_ids: string[];
  entitled_requesters: string[];
}

export interface CreateRolePayload {
  role_id: string;
  display_name: string;
  email?: string;
  passphrase: string;
  is_custodian?: boolean;
  evaluation_point?: number | null;
  notify_email?: boolean;
}

export interface IssueRecordPayload {
  owner_role_id: string;
  owner_passphrase: string;
  owner_otp: string;
  record_id: string;
  message_base64: string;
  custodian_role_ids: string[];
  threshold: number;
  entitled_requesters: string[];
}

export interface IssueRecordResponse {
  record_id: string;
  threshold: number;
  custodian_role_ids: string[];
  feldman_commitments: string[];
}

export interface RecoveryRequestOut {
  request_id: string;
  record_id: string;
  requester_role_id: string;
  approving_roles: string[];
  approvals_so_far: number;
  threshold: number | null;
  threshold_met: boolean;
}

export interface AuditEntry {
  seq: number;
  event_type: string;
  actor_id: string;
  data: Record<string, unknown>;
  timestamp: number;
  entry_hash: string;
}

export interface AuditVerifyResponse {
  ok: boolean;
  problems: string[];
}

export interface TamperDemoResponse {
  clean_verify: AuditVerifyResponse;
  tampered_verify: AuditVerifyResponse;
  what_was_tampered: string;
  note: string;
}

export interface SecurityTestResult {
  id: string;
  label: string;
  mechanism: string;
  group: string;
  expect: string;
  passed: boolean;
  detail: string;
}

export interface SecurityTestBattery {
  results: SecurityTestResult[];
  note: string;
}

export const api = {
  dashboardSummary: () => request<DashboardSummary>("/dashboard/summary"),
  listRoles: () => request<RoleOut[]>("/roles"),
  listRecords: () => request<RecordOut[]>("/records"),
  createRole: (payload: CreateRolePayload) =>
    request("/roles", { method: "POST", body: JSON.stringify(payload) }),
  getOtp: (roleId: string) =>
    request<{ role_id: string; otp: string }>(`/roles/${encodeURIComponent(roleId)}/otp`),
  issueRecord: (payload: IssueRecordPayload) =>
    request<IssueRecordResponse>("/records/issue", { method: "POST", body: JSON.stringify(payload) }),
  startRecovery: (payload: {
    request_id: string;
    record_id: string;
    requester_role_id: string;
    requester_passphrase: string;
    requester_otp: string;
  }) => request("/recovery/request", { method: "POST", body: JSON.stringify(payload) }),
  approveRecovery: (payload: {
    request_id: string;
    custodian_role_id: string;
    custodian_passphrase: string;
    custodian_otp: string;
  }) =>
    request<{ request_id: string; custodian_role_id: string; approvals_so_far: number }>(
      "/recovery/approve",
      { method: "POST", body: JSON.stringify(payload) }
    ),
  recoverRecord: (payload: { request_id: string; requester_passphrase: string; requester_otp: string }) =>
    request<{ record_id: string; message_base64: string }>("/recovery/recover", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  listRecoveryRequests: () => request<RecoveryRequestOut[]>("/recovery/requests"),
  authLogin: (payload: { email: string; passphrase: string }) =>
    request<{ role_id: string; display_name: string; email_hint: string; sent: boolean }>("/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  authVerify: (payload: { role_id: string; code: string }) =>
    request<{
      token: string;
      role_id: string;
      display_name: string;
      is_custodian: boolean;
      expires_in: number;
    }>("/auth/verify", { method: "POST", body: JSON.stringify(payload) }),
  auditLog: () => request<AuditEntry[]>("/audit/log"),
  auditVerify: () => request<AuditVerifyResponse>("/audit/verify"),
  tamperDemo: () => request<TamperDemoResponse>("/audit/tamper-demo", { method: "POST" }),
  runSecurityTests: () => request<SecurityTestBattery>("/security-tests/run", { method: "POST" }),
  carrierUrl: (recordId: string, roleId: string) =>
    `${BASE}/records/${encodeURIComponent(recordId)}/carrier/${encodeURIComponent(roleId)}`,
};

export { BASE as API_BASE };

export interface Candidate { candidate_id: string; candidate_name: string }
export interface Election { election_id: string; title: string; status: string; phase: string; revision: number;
  opens_at: string; closes_at: string; ra_ready: boolean; keyset_id: string | null; config_hash: string | null;
  candidates: Candidate[]; bundle: unknown }
export interface Keyset { keyset_id: string; ra_key: { key_id: string; fingerprint: string }; tally_key: { key_id: string; fingerprint: string } }
export interface AuditEvent { event_type: string; outcome: string; reason_code: string | null; occurred_at: string; actor_principal_id: string }
export class AdminFailure extends Error {
  readonly status: number;
  constructor(status = 503) {
    super(status === 401 ? 'Administrator sign-in is required.' : status === 409 ? 'Election changed or an operation is pending. Refresh before retrying the same operation.' : status === 422 ? 'Check the configuration fields.' : status === 429 ? 'Too many attempts. Wait before signing in again.' : 'Administrative service unavailable. Refresh to check whether the operation committed before retrying.');
    this.status = status;
  }
}
export function createAdminClient(transport: typeof fetch = (...args) => fetch(...args)) {
  // Independent closure: never exported to RA or anonymous Voting clients.
  let bearer: string | null = null;
  let epoch = 0;
  const forget = () => { bearer = null; epoch++; };
  async function request<T>(path: string, method = 'GET', data?: unknown): Promise<T> {
    // Callers cannot choose an origin or route outside the Admin boundary.
    if (!/^\/(auth\/(login|me|logout)|keysets|elections(?:\/[0-9a-f-]{36}(?:\/(?:audit|finalize|open|close|candidates(?:\/[0-9a-f-]{36})?))?)?)$/.test(path)) throw new AdminFailure(422);
    const generation = epoch;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    try {
      const response = await transport('/api/v1/admin' + path, { method, credentials: 'omit', cache: 'no-store',
        redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal,
        headers: { Accept: 'application/json', ...(data === undefined ? {} : { 'Content-Type': 'application/json' }),
          ...(path === '/auth/login' || !bearer ? {} : { Authorization: 'Bearer ' + bearer }) },
        ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
      if (generation !== epoch) throw new AdminFailure(401);
      if (!response.ok) {
        if (response.status === 401) forget();
        throw new AdminFailure(response.status);
      }
      const result: unknown = response.status === 204 ? undefined : await response.json();
      if (generation !== epoch) throw new AdminFailure(401);
      return result as T;
    } catch (error) { throw error instanceof AdminFailure ? error : new AdminFailure(); }
    finally { clearTimeout(timer); }
  }
  return { forget,
    async login(username: string, password: string) {
      forget();
      const result = await request<{ access_token: string; token_type: string }>('/auth/login', 'POST', { username, password });
      if (!/^adm1\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(result.access_token) || result.token_type !== 'bearer') throw new AdminFailure();
      bearer = result.access_token;
      const identity = await request<{ admin_id: string; role: string }>('/auth/me');
      if (identity.role !== 'ELECTION_ADMIN' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(identity.admin_id)) {
        forget(); throw new AdminFailure(401);
      }
    },
    async logout() { try { await request('/auth/logout', 'POST', {}); } finally { forget(); } },
    list: () => request<{ elections: Election[] }>('/elections'),
    keys: () => request<{ keysets: Keyset[] }>('/keysets'),
    detail: (id: string) => request<Election>('/elections/' + id),
    audit: (id: string) => request<{ events: AuditEvent[] }>('/elections/' + id + '/audit'),
    create: (data: unknown) => request<Election>('/elections', 'POST', data),
    change: (id: string, action: string, method: string, data: unknown) => request<Election>('/elections/' + id + action, method, data),
  };
}
export type AdminClient = ReturnType<typeof createAdminClient>;

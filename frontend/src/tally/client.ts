export interface TallyElection { election_id: string; title: string; status: 'CLOSED' | 'TALLIED'; ra_ready: boolean }
export interface TallyReport { report: { election_id: string; snapshot_digest: string; accepted_total: number; valid_total: number; invalid_total: number; counted_total: number;
  candidate_counts: { candidate_id: string; vote_count: number }[]; invalid_reasons: { KEY_WRAP: number; AEAD: number; PLAINTEXT: number } };
  report_digest: string; signature: string; signing_key_id: string; candidates: { candidate_id: string; candidate_name: string }[] }
export class TallyFailure extends Error {
  readonly status: number;
  constructor(status = 503, code = '') {
    super(status === 401 ? 'Tally operator sign-in required.' : status === 409 ? 'The election is not ready or a tally is already active. Refresh before retrying.' : code === 'KEY_UNAVAILABLE' ? 'The assigned Tally key is unavailable. No result was committed.' : code === 'INTEGRITY' ? 'Tally integrity verification failed. No result is available.' : status === 429 ? 'Too many sign-in attempts. Please wait.' : 'Restricted Tally service unavailable. Check for a committed report before retrying.');
    this.status = status;
  }
}
export function createTallyClient(transport: typeof fetch = (...args) => fetch(...args)) {
  let bearer: string | null = null;
  let epoch = 0;
  const forget = () => { bearer = null; epoch++; };
  async function request<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
    if (!/^\/(auth\/(login|me|logout)|elections(?:\/[0-9a-f-]{36}\/(run|report))?)$/.test(path)) throw new TallyFailure();
    const controller = new AbortController(), generation = epoch;
    const timer = setTimeout(() => controller.abort(), 90_000);
    try {
      const response = await transport('/api/v1/tally' + path, { method, credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal,
        headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
          ...(bearer && path !== '/auth/login' ? { Authorization: 'Bearer ' + bearer } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      if (generation !== epoch) throw new TallyFailure(401);
      if (!response.ok) {
        if (response.status === 401) forget();
        let code = '';
        if (response.status === 503) {
          const value: unknown = await response.json().catch(() => null);
          if (value && typeof value === 'object' && 'code' in value && ['KEY_UNAVAILABLE', 'INTEGRITY'].includes(String(value.code))) code = String(value.code);
        }
        throw new TallyFailure(response.status, code);
      }
      const value: unknown = response.status === 204 ? undefined : await response.json();
      if (generation !== epoch) throw new TallyFailure(401);
      return value as T;
    } catch (error) { throw error instanceof TallyFailure ? error : new TallyFailure(); }
    finally { clearTimeout(timer); }
  }
  return { forget,
    async login(username: string, password: string) {
      forget();
      const result = await request<{ access_token: string; token_type: string }>('/auth/login', 'POST', { username, password });
      if (!/^tly1\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(result.access_token) || result.token_type !== 'bearer') throw new TallyFailure();
      bearer = result.access_token;
      const identity = await request<{ role: string }>('/auth/me');
      if (identity.role !== 'TALLY_OPERATOR') { forget(); throw new TallyFailure(401); }
    },
    async logout() { try { await request('/auth/logout', 'POST', {}); } finally { forget(); } },
    elections: () => request<{ elections: TallyElection[] }>('/elections'),
    run: (id: string) => request<TallyReport>('/elections/' + id + '/run', 'POST', {}),
    report: (id: string) => request<TallyReport>('/elections/' + id + '/report'),
  };
}
export type TallyClient = ReturnType<typeof createTallyClient>;

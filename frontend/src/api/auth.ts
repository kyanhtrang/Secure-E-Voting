export interface VoterIdentity { voter_id: string }
export type ApiCode = 'disabled' | 'credentials' | 'expired' | 'unavailable' | 'invalid' | 'rate-limit' | 'cancelled';
const messages: Record<ApiCode, string> = {
  disabled: 'Local sign-in is not enabled in this workspace.',
  credentials: 'The username or password is incorrect.',
  expired: 'Your session has ended. Please sign in again.',
  unavailable: 'The local RA service is unavailable. Check that the local demo launcher is running, then try again.',
  invalid: 'Check your sign-in details and try again.',
  'rate-limit': 'Too many sign-in attempts. Please wait before trying again.',
  cancelled: 'The request was cancelled. Please try again.',
};
export class ApiError extends Error {
  readonly code: ApiCode;
  readonly retryAfter: number | undefined;
  constructor(code: ApiCode, retryAfter?: number) {
    super(messages[code]); this.name = 'ApiError'; this.code = code; this.retryAfter = retryAfter;
  }
}
export function safeError(error: unknown): string {
  return error instanceof ApiError ? error.message : messages.unavailable;
}
const prefix = '/api/v1/ra/auth';
const tokenPattern = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export type AuthClient = ReturnType<typeof createAuthClient>;
export function createAuthClient(enabled: boolean, transport: typeof fetch = (...args) => fetch(...args)) {
  // This closure is the sole token owner. No token getter, storage, URL or logger.
  let bearer: string | null = null;
  let epoch = 0;
  const active = new Set<AbortController>();
  function forget() { bearer = null; epoch++; for (const request of active) request.abort(); active.clear(); }
  async function request(path: '/login' | '/me' | '/logout', method: 'GET' | 'POST', passwordBody?: string): Promise<{ response: Response; data: unknown }> {
    if (!enabled) throw new ApiError('disabled');
    if (path !== '/login' && !bearer) throw new ApiError('expired');
    const controller = new AbortController(); active.add(controller);
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
      const headers: Record<string, string> = { Accept: 'application/json' };
      if (passwordBody !== undefined) headers['Content-Type'] = 'application/json';
      if (path !== '/login') headers.Authorization = 'Bearer ' + bearer;
      const response = await transport(prefix + path, { method, headers, ...(passwordBody === undefined ? {} : { body: passwordBody }),
        credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal });
      // Keep the abort deadline active through JSON reading; never parse error bodies.
      const data: unknown = path !== '/logout' && response.status === 200 ? await response.json() : undefined;
      return { response, data };
    } catch { throw new ApiError('unavailable'); }
    finally { clearTimeout(timeout); active.delete(controller); }
  }
  function reject(response: Response, login = false): never {
    if (response.status === 401) {
      if (!login) forget();
      throw new ApiError(login ? 'credentials' : 'expired');
    }
    if (response.status === 429) {
      const seconds = Number(response.headers.get('Retry-After'));
      throw new ApiError('rate-limit', Number.isInteger(seconds) && seconds > 0 ? Math.min(seconds, 300) : undefined);
    }
    throw new ApiError(response.status === 422 ? 'invalid' : 'unavailable');
  }
  async function me(): Promise<VoterIdentity> {
    const generation = epoch;
    const { response, data } = await request('/me', 'GET');
    if (epoch !== generation) throw new ApiError('cancelled');
    if (response.status !== 200) reject(response);
    if (!object(data) || Object.keys(data).join() !== 'voter_id' || typeof data.voter_id !== 'string' || !uuidPattern.test(data.voter_id)) {
      throw new ApiError('unavailable');
    }
    return { voter_id: data.voter_id };
  }
  async function login(username: string, password: string): Promise<VoterIdentity> {
    forget(); const generation = epoch;
    try {
      const { response, data } = await request('/login', 'POST', JSON.stringify({ username, password }));
      if (epoch !== generation) throw new ApiError('cancelled');
      if (response.status !== 200) reject(response, true);
      if (!object(data) || Object.keys(data).sort().join() !== 'access_token,token_type'
        || data.token_type !== 'Bearer' || typeof data.access_token !== 'string' || !tokenPattern.test(data.access_token)) {
        throw new ApiError('unavailable');
      }
      bearer = data.access_token;
      return await me(); // No authenticated UI until the real /me confirms identity.
    } catch (error) { if (epoch === generation) forget(); throw error; }
  }
  async function logout(): Promise<void> {
    try {
      const { response } = await request('/logout', 'POST');
      if (response.status !== 204) reject(response);
    } finally { forget(); } // Network failure clears this device but is never a confirmed revocation.
  }
  return { login, me, logout, forget };
}

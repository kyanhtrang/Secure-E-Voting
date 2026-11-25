import { fields, unb64, canonical } from '../voting/crypto';

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
export class PublicationFailure extends AdminFailure {
  readonly uncertain: boolean;
  constructor(status = 503, uncertain = false) {
    super(status); this.uncertain = uncertain;
    this.message = status === 401 ? 'Administrator sign-in is required.' : status === 403 ? 'This administrator is not enrolled as a Publisher.'
      : status === 409 ? 'Election is not ready for publication or conflicts with committed evidence. Refresh its state.'
      : status === 422 ? 'The publication request was rejected.'
      : 'Publisher unavailable or evidence invalid. Refresh authoritative state before an explicit retry; the outcome may be unknown.';
  }
}
export interface PublicationResult { status: 'PUBLISHED'; election_id: string; bundle_digest: string;
  publication: { signature: string; manifest: { publication_key_id: string; [field: string]: unknown } } }
const electionId = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export function createAdminClient(transport: typeof fetch = (...args) => fetch(...args), publicationEnabled = false) {
  // Independent closure: never exported to RA or anonymous Voting clients.
  let bearer: string | null = null;
  let epoch = 0;
  const forget = () => { bearer = null; epoch++; };
  let publishing = false;
  async function publish(id: string): Promise<PublicationResult> {
    if (!publicationEnabled) throw new PublicationFailure();
    if (!bearer) throw new PublicationFailure(401);
    if (typeof id !== 'string' || id.length !== 36 || !electionId.test(id)) throw new PublicationFailure(422);
    if (publishing) throw new PublicationFailure(409);
    publishing = true;
    const generation = epoch, controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30_000);
    try {
      const response = await transport('/api/v1/publication/elections/' + id + '/publish', {
        method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal,
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', Authorization: 'Bearer ' + bearer }, body: '{}' });
      const discard = async () => { try { await response.body?.cancel(); } catch { /* No raw transport errors. */ } };
      if (generation !== epoch) { await discard(); throw new PublicationFailure(401); }
      if (!response.ok) {
        if (response.status === 401) forget();
        await discard();
        throw new PublicationFailure([401,403,409,422].includes(response.status) ? response.status : 503, ![401,403,409,422].includes(response.status));
      }
      if (response.status !== 200 || !response.body || response.headers.get('Cache-Control') !== 'no-store'
        || !response.headers.get('Content-Type')?.startsWith('application/json')) { await discard(); throw new PublicationFailure(503,true); }
      const reader = response.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
      try { while (true) { const next = await reader.read(); if (next.done) break; size += next.value.length;
        if (size > 8192) throw new PublicationFailure(503,true); chunks.push(next.value); } }
      finally { await reader.cancel(); }
      const raw = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { raw.set(chunk,offset); offset += chunk.length; }
      const value: unknown = JSON.parse(new TextDecoder('utf-8',{ fatal: true }).decode(raw));
      // This validates the acknowledgement, not the signed evidence chain. That
      // remains the independently pinned Public verifier's responsibility.
      fields(value,['status','election_id','bundle_digest','publication']);
      const hash = (item: unknown) => typeof item === 'string' && item.length === 64 && /^[0-9a-f]{64}$/.test(item);
      if (value.status !== 'PUBLISHED' || value.election_id !== id || !hash(value.bundle_digest)) throw new PublicationFailure(503,true);
      fields(value.publication,['manifest','signature']); unb64(value.publication.signature,64);
      const manifest = value.publication.manifest;
      fields(manifest,['manifest_version','election_id','election_config_digest','snapshot_digest','tally_report_digest','accepted_total','valid_total','invalid_total','counted_total','publication_key_id','signature_algorithm']);
      if (manifest.manifest_version !== 1 || manifest.election_id !== id || manifest.signature_algorithm !== 'Ed25519'
        || typeof manifest.publication_key_id !== 'string' || manifest.publication_key_id.match(/^[a-z0-9][a-z0-9._-]{0,127}$/)?.[0] !== manifest.publication_key_id) throw new PublicationFailure(503,true);
      for (const field of ['election_config_digest','snapshot_digest','tally_report_digest']) if (!hash(manifest[field])) throw new PublicationFailure(503,true);
      for (const field of ['accepted_total','valid_total','invalid_total','counted_total']) if (!Number.isSafeInteger(manifest[field]) || (manifest[field] as number) < 0) throw new PublicationFailure(503,true);
      if (manifest.accepted_total !== (manifest.valid_total as number) + (manifest.invalid_total as number) || manifest.counted_total !== manifest.valid_total
        || new TextDecoder().decode(canonical(value)) !== new TextDecoder().decode(raw)) throw new PublicationFailure(503,true);
      if (generation !== epoch) throw new PublicationFailure(401);
      if (controller.signal.aborted) throw new PublicationFailure(503,true);
      return value as unknown as PublicationResult;
    } catch (error) { throw error instanceof PublicationFailure ? error : new PublicationFailure(503,true); }
    finally { clearTimeout(timer); publishing = false; }
  }
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
  return { forget, publish,
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

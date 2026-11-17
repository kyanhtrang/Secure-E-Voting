import { fields, messageBytes, requireValid, type Ballot } from './crypto';

export type FlowCode = 'unavailable' | 'session' | 'denied' | 'reserved' | 'recovery-expired' | 'invalid' | 'conflict' | 'not-found';
const messages: Record<FlowCode,string> = {
  unavailable:'The service could not confirm this operation. Keep your recovery state and retry the same request.',
  session:'Your RA session has ended. Sign in with the original account to recover the same request.',
  denied:'The RA did not authorize issuance. Eligibility, active status and the issuance window are checked by the RA.',
  reserved:'An authorization already exists. Restore its original recovery file; do not create another request.',
  'recovery-expired':'The RA recovery deadline has passed. Eligibility cannot be reset by this browser.',
  invalid:'The server rejected this credential or ballot. Keep the existing recovery state.',
  conflict:'The credential may already be spent, or the election is closed. Check the existing receipt.',
  'not-found':'No matching receipt was found yet. This does not prove an earlier request cannot still commit.',
};
export class FlowError extends Error { readonly code: FlowCode; constructor(code: FlowCode) { super(messages[code]); this.code=code; } }
export function flowMessage(error: unknown): string { return error instanceof FlowError ? error.message : 'Verification or protected storage failed. Keep your existing recovery file; no replacement credential will be generated.'; }
export function raFailure(status: number): never { throw new FlowError(status === 401 ? 'session' : status === 403 ? 'denied' : status === 409 ? 'reserved' : status === 410 ? 'recovery-expired' : status === 422 ? 'invalid' : 'unavailable'); }

export function anonymousClient(enabled: boolean, transport: typeof fetch=(...args)=>fetch(...args)) {
  async function send(ballot: Ballot, recovery: boolean): Promise<string> {
    if (!enabled) throw new FlowError('unavailable');
    fields(ballot.credential,['message','prepared_msg','signature']); messageBytes(ballot.credential.message);
    fields(ballot.envelope,['schema_version','key_id','cipher_algorithm','key_wrap_algorithm','nonce','ciphertext','encrypted_key']);
    // Reconstruct the exact allowlist; never spread RA/recovery objects into this request.
    const body={election_id:ballot.election_id,credential:ballot.credential,envelope:ballot.envelope};
    const controller=new AbortController(), timeout=setTimeout(()=>controller.abort(),15000);
    try {
      const response=await transport('/api/v1/vote/ballots'+(recovery ? '/receipt' : ''),{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify(body),credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',signal:controller.signal});
      if (response.status !== (recovery ? 200 : 201)) throw new FlowError(response.status === 409 ? 'conflict' : response.status === 404 ? 'not-found' : response.status === 422 ? 'invalid' : 'unavailable');
      const data: unknown=await response.json(); fields(data,['status','receipt_hash']);
      requireValid(data.status === 'accepted' && typeof data.receipt_hash === 'string' && data.receipt_hash.match(/^[0-9a-f]{64}$/)?.[0] === data.receipt_hash);
      return data.receipt_hash;
    } catch (error) { if (error instanceof FlowError) throw error; throw new FlowError('unavailable'); }
    finally { clearTimeout(timeout); }
  }
  return { submit:(ballot: Ballot)=>send(ballot,false), recover:(ballot: Ballot)=>send(ballot,true) };
}

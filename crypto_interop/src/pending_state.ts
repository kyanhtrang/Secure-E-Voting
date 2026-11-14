// Client-only protected pending state. Never POST this object to RA.
import { randomBytes, scryptSync, createCipheriv, createDecipheriv, randomUUID } from 'node:crypto';
import { open, link, unlink, readFile } from 'node:fs/promises';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { b64, unb64, fields, jcs, messageBytes, requireValid, uuid, hash, verifyManifest, DOMAIN, type ObjectValue } from './protocol.js';

const CONTEXT = Buffer.from('EVOTE-CLIENT-PENDING-v1\0');
function validate(state: unknown): asserts state is ObjectValue {
  fields(state, ['version', 'request_id', 'message', 'prepared_msg', 'blinded_msg', 'inv', 'key_fingerprint']);
  requireValid(state.version === 1); uuid(state.request_id); hash(state.key_fingerprint);
  const canonical = messageBytes(state.message);
  const prepared = unb64(state.prepared_msg);
  requireValid(prepared.length === 32+canonical.length && prepared.subarray(32).equals(canonical));
  unb64(state.blinded_msg,384); unb64(state.inv,384);
}
function derive(passphrase: string, salt: Uint8Array) {
  requireValid(typeof passphrase === 'string' && passphrase.length >= 12 && passphrase.length <= 1024);
  return scryptSync(passphrase,salt,32,{N:65536,r:8,p:1,maxmem:128*1024*1024});
}
export function issuePayload(state: unknown) {
  validate(state);
  return {election_id:(state.message as ObjectValue).election_id,
    request_id:state.request_id as string,blinded_msg:state.blinded_msg as string};
}
export async function preparePending(path: string, passphrase: string, bundle: unknown,
  pinnedAuthority: string, electionId: string, envelopeHash: string) {
  const {manifest,configHash}=await verifyManifest(bundle,pinnedAuthority,electionId);
  hash(envelopeHash);
  const ra=manifest.ra_key as ObjectValue;
  const key=await crypto.subtle.importKey('spki',unb64(ra.spki),{name:'RSA-PSS',hash:'SHA-384'},true,['verify']);
  const message={domain:DOMAIN,version:2,election_id:electionId,serial:b64(randomBytes(32)),
    envelope_hash:envelopeHash,config_hash:configHash,key_id:ra.key_id};
  const suite=RSABSSA.SHA384.PSS.Randomized();
  const prepared=suite.prepare(messageBytes(message));
  const {blindedMsg,inv}=await suite.blind(key,prepared);
  return persistBeforeIssue(path,{version:1,request_id:randomUUID(),message,prepared_msg:b64(prepared),
    blinded_msg:b64(blindedMsg),inv:b64(inv),key_fingerprint:ra.fingerprint},passphrase);
}
export async function finalizePending(path: string, passphrase: string, blindSignature: string,
  bundle: unknown, pinnedAuthority: string, electionId: string) {
  const state=await loadPending(path,passphrase) as ObjectValue;
  const {manifest,configHash}=await verifyManifest(bundle,pinnedAuthority,electionId);
  const ra=manifest.ra_key as ObjectValue, message=state.message as ObjectValue;
  requireValid(message.election_id===electionId && message.config_hash===configHash
    && message.key_id===ra.key_id && state.key_fingerprint===ra.fingerprint);
  const key=await crypto.subtle.importKey('spki',unb64(ra.spki),{name:'RSA-PSS',hash:'SHA-384'},true,['verify']);
  const signature=await RSABSSA.SHA384.PSS.Randomized().finalize(key,unb64(state.prepared_msg),
    unb64(blindSignature,384),unb64(state.inv,384));
  // The caller must protect the final credential as well; it never goes to RA.
  return {message,prepared_msg:state.prepared_msg,signature:b64(signature)};
}
export async function persistBeforeIssue(path: string, state: unknown, passphrase: string) {
  validate(state);
  const salt=randomBytes(16), nonce=randomBytes(12), key=derive(passphrase,salt);
  const cipher=createCipheriv('aes-256-gcm',key,nonce); cipher.setAAD(CONTEXT);
  const encrypted=Buffer.concat([cipher.update(jcs(state)),cipher.final()]); key.fill(0);
  const file=jcs({version:1,salt:b64(salt),nonce:b64(nonce),ciphertext:b64(encrypted),tag:b64(cipher.getAuthTag())});
  const temporary=path+'.'+randomUUID()+'.tmp';
  let handle;
  try {
    handle=await open(temporary,'wx',0o600); await handle.writeFile(file); await handle.sync();
    await handle.close(); handle=undefined;
    await link(temporary,path); // Atomic no-replace publication; existing state is sacred.
    return issuePayload(state); // No request leaves this helper before persistence.
  } finally {
    if (handle) await handle.close();
    await unlink(temporary).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'ENOENT') throw error; });
  }
}
export async function loadPending(path: string, passphrase: string) {
  const contents=await readFile(path); requireValid(contents.length <= 32768);
  const envelope=JSON.parse(contents.toString('utf8')) as ObjectValue;
  fields(envelope,['version','salt','nonce','ciphertext','tag']);
  requireValid(envelope.version===1 && jcs(envelope).equals(contents));
  const key=derive(passphrase,unb64(envelope.salt,16));
  try {
    const decipher=createDecipheriv('aes-256-gcm',key,unb64(envelope.nonce,12));
    decipher.setAAD(CONTEXT); decipher.setAuthTag(unb64(envelope.tag,16));
    const plain=Buffer.concat([decipher.update(unb64(envelope.ciphertext)),decipher.final()]);
    const state=JSON.parse(plain.toString('utf8')) as unknown;
    requireValid(jcs(state).equals(plain)); validate(state);
    return state;
  } finally { key.fill(0); }
}

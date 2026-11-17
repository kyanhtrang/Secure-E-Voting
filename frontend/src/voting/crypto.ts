// Browser adapter for the frozen v2 wire protocol. No Node APIs or signing keys.
import canonicalize from 'canonicalize';
import { RSABSSA } from '@cloudflare/blindrsa-ts';

export const PROFILE = 'RSABSSA-SHA384-PSS-Randomized';
const DOMAIN = 'secure-evoting-blind-credential-v2';
export class CryptoFailure extends Error { constructor() { super('Cryptographic verification failed.'); } }
export function requireValid(value: unknown): asserts value { if (!value) throw new CryptoFailure(); }
export function fields(value: unknown, names: string[]): asserts value is Record<string, unknown> {
  requireValid(value !== null && typeof value === 'object' && !Array.isArray(value));
  requireValid(Object.keys(value).sort().join() === [...names].sort().join());
}
export function canonical(value: unknown): Uint8Array<ArrayBuffer> {
  const text = canonicalize(value); requireValid(typeof text === 'string'); return new TextEncoder().encode(text);
}
export function b64(raw: Uint8Array): string { return btoa(Array.from(raw, value => String.fromCharCode(value)).join('')).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, ''); }
export function unb64(value: unknown, length?: number, maximum=12000): Uint8Array<ArrayBuffer> {
  requireValid(typeof value === 'string' && value.length > 0 && value.length <= maximum && value.match(/^[A-Za-z0-9_-]+$/)?.[0] === value);
  let bytes: Uint8Array<ArrayBuffer>;
  try { bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')+'='.repeat((4-value.length%4)%4)), char => char.charCodeAt(0)); }
  catch { throw new CryptoFailure(); }
  requireValid(b64(bytes) === value && (length === undefined || bytes.length === length)); return bytes;
}
export function uuid(value: unknown): asserts value is string { requireValid(typeof value === 'string' && value.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)?.[0] === value); }
function keyId(value: unknown) { requireValid(typeof value === 'string' && value.match(/^[a-z0-9][a-z0-9._-]{0,127}$/)?.[0] === value); }
function hash(value: unknown) { requireValid(typeof value === 'string' && value.match(/^[0-9a-f]{64}$/)?.[0] === value); }
export async function sha256(raw: Uint8Array<ArrayBuffer>): Promise<string> { return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', raw)), value => value.toString(16).padStart(2, '0')).join(''); }
function join(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> { const result = new Uint8Array(parts.reduce((size, part) => size+part.length, 0)); let offset=0; for (const part of parts) { result.set(part, offset); offset+=part.length; } return result; }
export interface PublicKeyInfo { key_id: string; spki: string; fingerprint: string }
export interface Manifest { domain: string; version: number; election_id: string; opens_at: string; closes_at: string; candidates: { candidate_id: string; candidate_name: string }[]; ra_key: PublicKeyInfo; tally_key: PublicKeyInfo; profile: string }
export interface Bundle { manifest: Manifest; signature: string }
export interface Message { domain: string; version: number; election_id: string; serial: string; envelope_hash: string; config_hash: string; key_id: string }
export interface Proof { message: Message; prepared_msg: string; signature: string }
export interface Envelope { schema_version: number; key_id: string; cipher_algorithm: string; key_wrap_algorithm: string; nonce: string; ciphertext: string; encrypted_key: string }
export interface Pending { version: number; request_id: string; message: Message; prepared_msg: string; blinded_msg: string; inv: string; key_fingerprint: string }
export interface Ballot { election_id: string; credential: Proof; envelope: Envelope }

async function rsa(info: PublicKeyInfo, usage: 'verify' | 'encrypt'): Promise<CryptoKey> {
  const algorithm = usage === 'verify' ? { name: 'RSA-PSS', hash: 'SHA-384' } : { name: 'RSA-OAEP', hash: 'SHA-256' };
  const key = await crypto.subtle.importKey('spki', unb64(info.spki), algorithm, true, [usage]);
  const details = key.algorithm as RsaHashedKeyAlgorithm;
  requireValid(details.modulusLength === 3072 && b64(details.publicExponent) === 'AQAB');
  requireValid(b64(new Uint8Array(await crypto.subtle.exportKey('spki', key))) === info.spki);
  return key;
}
export async function verifyManifest(bundle: unknown, pin: string, election: string): Promise<Bundle> {
  fields(bundle, ['manifest', 'signature']); uuid(election);
  const manifest = bundle.manifest;
  fields(manifest, ['domain','version','election_id','opens_at','closes_at','candidates','ra_key','tally_key','profile']);
  requireValid(manifest.domain === 'secure-evoting-election-manifest-v1' && manifest.version === 1 && manifest.profile === PROFILE);
  uuid(manifest.election_id); requireValid(manifest.election_id === election);
  const times: number[]=[];
  for (const field of ['opens_at','closes_at']) {
    const value=manifest[field]; requireValid(typeof value === 'string' && value.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)?.[0] === value);
    const time=new Date(value); requireValid(Number.isFinite(time.getTime()) && time.toISOString() === value.replace('Z','.000Z')); times.push(time.getTime());
  }
  requireValid(times[0]! < times[1]!);
  requireValid(Array.isArray(manifest.candidates) && manifest.candidates.length >= 1 && manifest.candidates.length <= 1000);
  const ids: string[]=[];
  for (const candidate of manifest.candidates) {
    fields(candidate,['candidate_id','candidate_name']); uuid(candidate.candidate_id); ids.push(candidate.candidate_id);
    const name=candidate.candidate_name;
    requireValid(typeof name === 'string' && Array.from(name).length >= 1 && Array.from(name).length <= 128 && name.trim() === name && name.normalize('NFC') === name && !/[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(name));
  }
  requireValid(JSON.stringify(ids) === JSON.stringify([...new Set(ids)].sort()));
  for (const field of ['ra_key','tally_key']) {
    const key=manifest[field]; fields(key,['key_id','spki','fingerprint']); keyId(key.key_id);
    requireValid(await sha256(unb64(key.spki)) === key.fingerprint);
    await rsa(key as unknown as PublicKeyInfo, field === 'ra_key' ? 'verify' : 'encrypt');
  }
  const result=bundle as unknown as Bundle;
  requireValid(result.manifest.ra_key.fingerprint !== result.manifest.tally_key.fingerprint);
  const authority=await crypto.subtle.importKey('raw',unb64(pin,32),'Ed25519',false,['verify']);
  requireValid(await crypto.subtle.verify('Ed25519',authority,unb64(bundle.signature,64),join(new TextEncoder().encode('EVOTE-MANIFEST-v1\0'),canonical(manifest))));
  return result;
}
export function messageBytes(message: unknown): Uint8Array<ArrayBuffer> {
  fields(message,['domain','version','election_id','serial','envelope_hash','config_hash','key_id']);
  requireValid(message.domain === DOMAIN && message.version === 2); uuid(message.election_id); unb64(message.serial,32); hash(message.envelope_hash); hash(message.config_hash); keyId(message.key_id);
  return canonical(message);
}
export function validateEnvelope(envelope: unknown, manifest: Manifest): asserts envelope is Envelope {
  fields(envelope,['schema_version','key_id','cipher_algorithm','key_wrap_algorithm','nonce','ciphertext','encrypted_key']);
  requireValid(envelope.schema_version === 1 && envelope.key_id === manifest.tally_key.key_id && envelope.cipher_algorithm === 'AES-256-GCM' && envelope.key_wrap_algorithm === 'RSA-OAEP-SHA256');
  unb64(envelope.nonce,12); unb64(envelope.encrypted_key,384);
  const cipher=unb64(envelope.ciphertext); requireValid(cipher.length >= 17 && cipher.length <= 8192 && canonical(envelope).length <= 16384);
}
export function windowStatus(manifest: Manifest, now=Date.now()): 'upcoming' | 'open' | 'closed' { return now < Date.parse(manifest.opens_at) ? 'upcoming' : now >= Date.parse(manifest.closes_at) ? 'closed' : 'open'; }
export async function prepareBallot(bundle: Bundle, pin: string, candidateId: string): Promise<{ pending: Pending; envelope: Envelope }> {
  await verifyManifest(bundle,pin,bundle.manifest.election_id);
  const manifest=bundle.manifest; requireValid(windowStatus(manifest) === 'open');
  requireValid(manifest.candidates.some(candidate => candidate.candidate_id === candidateId));
  const serial=crypto.getRandomValues(new Uint8Array(32)), nonce=crypto.getRandomValues(new Uint8Array(12)), aes=crypto.getRandomValues(new Uint8Array(32));
  const aad=canonical({schema_version:1,election_id:manifest.election_id,serial:b64(serial)});
  let ciphertext:ArrayBuffer, wrapped:ArrayBuffer;
  try {
    const key=await crypto.subtle.importKey('raw',aes,'AES-GCM',false,['encrypt']);
    ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},key,canonical({schema_version:1,election_id:manifest.election_id,candidate_id:candidateId}));
    wrapped=await crypto.subtle.encrypt({name:'RSA-OAEP'},await rsa(manifest.tally_key,'encrypt'),aes);
  } finally { aes.fill(0); }
  const envelope: Envelope={schema_version:1,key_id:manifest.tally_key.key_id,cipher_algorithm:'AES-256-GCM',key_wrap_algorithm:'RSA-OAEP-SHA256',nonce:b64(nonce),ciphertext:b64(new Uint8Array(ciphertext)),encrypted_key:b64(new Uint8Array(wrapped))};
  validateEnvelope(envelope,manifest);
  const message: Message={domain:DOMAIN,version:2,election_id:manifest.election_id,serial:b64(serial),envelope_hash:await sha256(canonical(envelope)),config_hash:await sha256(canonical(manifest)),key_id:manifest.ra_key.key_id};
  const suite=RSABSSA.SHA384.PSS.Randomized(), prepared=suite.prepare(messageBytes(message));
  const {blindedMsg,inv}=await suite.blind(await rsa(manifest.ra_key,'verify'),prepared);
  return {envelope,pending:{version:1,request_id:crypto.randomUUID(),message,prepared_msg:b64(prepared),blinded_msg:b64(blindedMsg),inv:b64(inv),key_fingerprint:manifest.ra_key.fingerprint}};
}
export function issuePayload(pending: Pending) { return { election_id:pending.message.election_id,request_id:pending.request_id,blinded_msg:pending.blinded_msg }; }
export async function verifyProof(proof: Proof, envelope: Envelope, bundle: Bundle, pin: string): Promise<void> {
  await verifyManifest(bundle,pin,bundle.manifest.election_id); validateEnvelope(envelope,bundle.manifest);
  fields(proof,['message','prepared_msg','signature']);
  const encoded=messageBytes(proof.message), prepared=unb64(proof.prepared_msg);
  requireValid(prepared.length === 32+encoded.length && b64(prepared.slice(32)) === b64(encoded));
  requireValid(proof.message.election_id === bundle.manifest.election_id && proof.message.config_hash === await sha256(canonical(bundle.manifest)) && proof.message.key_id === bundle.manifest.ra_key.key_id && proof.message.envelope_hash === await sha256(canonical(envelope)));
  requireValid(await crypto.subtle.verify({name:'RSA-PSS',saltLength:48},await rsa(bundle.manifest.ra_key,'verify'),unb64(proof.signature,384),prepared));
}
export async function finalize(pending: Pending, signature: string, envelope: Envelope, bundle: Bundle, pin: string): Promise<Proof> {
  const signed=await RSABSSA.SHA384.PSS.Randomized().finalize(await rsa(bundle.manifest.ra_key,'verify'),unb64(pending.prepared_msg),unb64(signature,384),unb64(pending.inv,384));
  const proof={message:pending.message,prepared_msg:pending.prepared_msg,signature:b64(signed)};
  await verifyProof(proof,envelope,bundle,pin); return proof;
}
export async function receipt(ballot: Ballot): Promise<string> {
  const proof=ballot.credential;
  return sha256(join(new TextEncoder().encode('EVOTE-RECEIPT-v1\0'),canonical({election_id:ballot.election_id,serial:proof.message.serial,envelope_hash:proof.message.envelope_hash,prepared_msg:proof.prepared_msg,signature:proof.signature})));
}

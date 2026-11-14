import canonicalize from 'canonicalize';
import { createHash, createPublicKey } from 'node:crypto';

export const PROFILE = 'RSABSSA-SHA384-PSS-Randomized';
export const DOMAIN = 'secure-evoting-blind-credential-v2';
export const MANIFEST_DOMAIN = 'secure-evoting-election-manifest-v1';
export const MANIFEST_CONTEXT = Buffer.from('EVOTE-MANIFEST-v1\0', 'utf8');
export type ObjectValue = Record<string, unknown>;

export function requireValid(condition: unknown): asserts condition {
  if (!condition) throw new Error('Invalid cryptographic protocol input');
}
export function fields(value: unknown, names: string[]): asserts value is ObjectValue {
  requireValid(value !== null && typeof value === 'object' && !Array.isArray(value));
  requireValid(Object.keys(value).sort().join(',') === [...names].sort().join(','));
}
export function jcs(value: unknown): Buffer<ArrayBuffer> {
  const encoded = canonicalize(value);
  requireValid(typeof encoded === 'string');
  return Buffer.from(encoded, 'utf8');
}
export function b64(value: Uint8Array): string { return Buffer.from(value).toString('base64url'); }
export function unb64(value: unknown, length?: number): Buffer<ArrayBuffer> {
  requireValid(typeof value === 'string' && value.length > 0 && value.length <= 12000 && /^[A-Za-z0-9_-]+$/.test(value));
  const raw = Buffer.from(value, 'base64url');
  requireValid(b64(raw) === value && (length === undefined || raw.length === length));
  return raw;
}
export function uuid(value: unknown): asserts value is string {
  requireValid(typeof value === 'string' && value.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)?.[0] === value);
}
export function keyId(value: unknown): asserts value is string {
  requireValid(typeof value === 'string' && value.match(/^[a-z0-9][a-z0-9._-]{0,127}$/)?.[0] === value);
}
export function hash(value: unknown): asserts value is string {
  requireValid(typeof value === 'string' && value.match(/^[0-9a-f]{64}$/)?.[0] === value);
}
export function sha256(value: Uint8Array): string { return createHash('sha256').update(value).digest('hex'); }
export function messageBytes(value: unknown): Buffer {
  fields(value, ['domain', 'version', 'election_id', 'serial', 'envelope_hash', 'config_hash', 'key_id']);
  requireValid(value.domain === DOMAIN && value.version === 2);
  uuid(value.election_id); unb64(value.serial, 32);
  hash(value.envelope_hash); hash(value.config_hash); keyId(value.key_id);
  return jcs(value);
}
export function rsaPublic(spki: unknown, bits = 3072) {
  const raw = unb64(spki);
  const key = createPublicKey({key: raw, type: 'spki', format: 'der'});
  requireValid(key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails?.modulusLength === bits
    && key.asymmetricKeyDetails.publicExponent === 65537n);
  requireValid(key.export({type: 'spki', format: 'der'}).equals(raw));
  return key;
}
export function manifestBytes(value: unknown): Buffer {
  fields(value, ['domain', 'version', 'election_id', 'opens_at', 'closes_at', 'candidates', 'ra_key', 'tally_key', 'profile']);
  requireValid(value.domain === MANIFEST_DOMAIN && value.version === 1 && value.profile === PROFILE);
  uuid(value.election_id);
  const times: number[] = [];
  for (const name of ['opens_at', 'closes_at']) {
    const item = value[name];
    requireValid(typeof item === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(item));
    const date = new Date(item);
    requireValid(Number.isFinite(date.getTime()) && date.toISOString() === item.replace('Z', '.000Z'));
    times.push(date.getTime());
  }
  requireValid(times[0]! < times[1]!);
  requireValid(Array.isArray(value.candidates) && value.candidates.length >= 1 && value.candidates.length <= 1000);
  const ids: string[] = [];
  for (const candidate of value.candidates) {
    fields(candidate, ['candidate_id', 'candidate_name']); uuid(candidate.candidate_id);
    ids.push(candidate.candidate_id);
    const name = candidate.candidate_name;
    requireValid(typeof name === 'string' && Array.from(name).length > 0 && Array.from(name).length <= 128
      && name === name.trim() && name.normalize('NFC') === name && !/[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(name));
  }
  requireValid(JSON.stringify(ids) === JSON.stringify([...new Set(ids)].sort()));
  const fingerprints: string[] = [];
  for (const name of ['ra_key', 'tally_key']) {
    const key = value[name]; fields(key, ['key_id', 'spki', 'fingerprint']); keyId(key.key_id);
    rsaPublic(key.spki);
    const expected = sha256(unb64(key.spki));
    requireValid(key.fingerprint === expected); fingerprints.push(expected);
  }
  requireValid(fingerprints[0] !== fingerprints[1]);
  return jcs(value);
}
export async function verifyManifest(bundle: unknown, pinned: unknown, expectedElection: unknown) {
  fields(bundle, ['manifest', 'signature']); uuid(expectedElection);
  const encoded = manifestBytes(bundle.manifest);
  const publicKey = await crypto.subtle.importKey('raw', unb64(pinned, 32), 'Ed25519', false, ['verify']);
  requireValid(await crypto.subtle.verify('Ed25519', publicKey, unb64(bundle.signature, 64),
    Buffer.concat([MANIFEST_CONTEXT, encoded])));
  const manifest = bundle.manifest as ObjectValue;
  requireValid(manifest.election_id === expectedElection);
  return {manifest, configHash: sha256(encoded)};
}

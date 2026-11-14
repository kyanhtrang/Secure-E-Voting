// Test driver only: no HTTP, auth, database, or private signing-key input.
import { RSABSSA, BlindRSA } from '@cloudflare/blindrsa-ts';
import { randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import { mock } from 'node:test';
import {
  DOMAIN, b64, unb64, fields, hash, jcs, messageBytes, requireValid, rsaPublic, verifyManifest,
  type ObjectValue,
} from './protocol.js';

const suite = RSABSSA.SHA384.PSS.Randomized();
type Pending = {key: CryptoKey; prepared: Uint8Array; inv: Uint8Array; suite: BlindRSA; message?: ObjectValue; rfc: boolean};
const pending = new Map<string, Pending>();
let sequence = 0;

async function publicKey(spki: unknown, rfc = false) {
  rsaPublic(spki, rfc ? 4096 : 3072);
  return crypto.subtle.importKey('spki', unb64(spki), {name: 'RSA-PSS', hash: 'SHA-384'}, true, ['verify']);
}
async function prepare(request: ObjectValue, wrongSalt: boolean) {
  fields(request, ['op', 'bundle', 'pinned_root', 'expected_election', 'envelope_hash']);
  const {manifest, configHash} = await verifyManifest(request.bundle, request.pinned_root, request.expected_election);
  hash(request.envelope_hash);
  const ra = manifest.ra_key as ObjectValue;
  const message = {domain: DOMAIN, version: 2, election_id: manifest.election_id,
    serial: b64(randomBytes(32)), envelope_hash: request.envelope_hash,
    config_hash: configHash, key_id: ra.key_id};
  const key = await publicKey(ra.spki);
  // Wrong salt is solely a negative-test construction, never protocol negotiation.
  const selected = wrongSalt ? new BlindRSA({...suite.params, saltLength: 0}) : suite;
  const encoded = messageBytes(message);
  const prepared = selected.prepare(encoded);
  const {blindedMsg, inv} = await selected.blind(key, prepared);
  const handle = String(++sequence);
  pending.set(handle, {key, prepared, inv, suite: selected, message, rfc: false});
  return {handle, message, canonical_msg: b64(encoded), prepared_msg: b64(prepared), blinded_msg: b64(blindedMsg)};
}
async function rfcPrepare(request: ObjectValue) {
  fields(request, ['op', 'spki', 'msg', 'prefix', 'salt', 'random_blind', 'expected_inverse']);
  const key = await publicKey(request.spki, true);
  const values = [unb64(request.prefix, 32), unb64(request.salt, 48), unb64(request.random_blind, 512)];
  let index = 0;
  // Same fixed-randomness strategy as the upstream RFC test, restored in finally.
  const replacement = mock.method(crypto, 'getRandomValues', ((array: Uint8Array) => {
    const next = values[index++];
    requireValid(next && next.length === array.length);
    array.set(next); return array;
  }) as typeof crypto.getRandomValues);
  let prepared: Uint8Array;
  let blindedMsg: Uint8Array;
  let inv: Uint8Array;
  try {
    prepared = suite.prepare(unb64(request.msg));
    ({blindedMsg, inv} = await suite.blind(key, prepared));
    requireValid(index === 3 && b64(inv) === request.expected_inverse);
  } finally { replacement.mock.restore(); }
  const handle = String(++sequence);
  pending.set(handle, {key, prepared, inv, suite, rfc: true});
  return {handle, prepared_msg: b64(prepared), blinded_msg: b64(blindedMsg)};
}
async function dispatch(request: ObjectValue) {
  switch (request.op) {
    case 'canonicalize':
      fields(request, ['op', 'message']); return {canonical_msg: b64(messageBytes(request.message))};
    case 'verify_manifest': {
      fields(request, ['op', 'bundle', 'pinned_root', 'expected_election']);
      const result = await verifyManifest(request.bundle, request.pinned_root, request.expected_election);
      return {config_hash: result.configHash};
    }
    case 'prepare': return prepare(request, false);
    case 'prepare_wrong_salt': return prepare(request, true);
    case 'rfc_prepare': return rfcPrepare(request);
    case 'finalize': {
      fields(request, ['op', 'handle', 'blind_sig']);
      requireValid(typeof request.handle === 'string');
      const state = pending.get(request.handle); requireValid(state);
      const blindSignature = unb64(request.blind_sig, state.rfc ? 512 : 384);
      // The negative fixture finalizes with its deliberately wrong suite;
      // Python's fixed profile must reject that otherwise-valid signature.
      const signature = await state.suite.finalize(state.key, state.prepared, blindSignature, state.inv);
      pending.delete(request.handle);
      return { ...(state.rfc ? {} : {message: state.message}),
        prepared_msg: b64(state.prepared), signature: b64(signature)};
    }
    default: throw new Error('Invalid crypto test operation');
  }
}
async function main() {
  for await (const line of createInterface({input: process.stdin, crlfDelay: Infinity})) {
    try {
      requireValid(Buffer.byteLength(line) <= 131072);
      const request = JSON.parse(line) as ObjectValue;
      // Canonical JSONL test transport also rejects duplicate keys.
      requireValid(jcs(request).toString('utf8') === line);
      console.log(JSON.stringify(await dispatch(request)));
    } catch { console.log(JSON.stringify({error: 'Invalid crypto test input'})); }
  }
}
main().catch(() => { console.error('Crypto test client failed'); process.exitCode = 1; });

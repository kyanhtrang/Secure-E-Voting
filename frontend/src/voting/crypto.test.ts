// @vitest-environment node
import { beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { BlindRSA, RSABSSA } from '@cloudflare/blindrsa-ts';
import { b64, canonical, finalize, issuePayload, messageBytes, prepareBallot, receipt, unb64, verifyManifest, verifyProof, windowStatus, type Proof } from './crypto';
import { testMaterial } from './material.test-support';
import { protect, unlock, type PrivateState } from './recovery';

let material:Awaited<ReturnType<typeof testMaterial>>, prepared:Awaited<ReturnType<typeof prepareBallot>>, proof:Proof;
beforeAll(async()=>{
  material=await testMaterial();prepared=await prepareBallot(material.bundle,material.pin,material.bundle.manifest.candidates[0]!.candidate_id);
  const blind=await RSABSSA.SHA384.PSS.Randomized().blindSign(material.ra.privateKey,unb64(prepared.pending.blinded_msg));
  proof=await finalize(prepared.pending,b64(blind),prepared.envelope,material.bundle,material.pin);
});
describe('real browser protocol adapter',()=>{
  it('matches every frozen credential serialization vector',()=>{
    const vectors=JSON.parse(readFileSync(new URL('../../../crypto_interop/vectors/credential-v2.json',import.meta.url),'utf8')) as {message:unknown;canonical_utf8:string}[];
    for(const vector of vectors)expect(new TextDecoder().decode(messageBytes(vector.message))).toBe(vector.canonical_utf8);
  });
  it('performs real BlindSign/finalization and independent frozen Python verification',()=>{
    const code="import sys,json,hashlib,rfc8785; from backend.crypto.credential_protocol import verify_credential,b64decode; x=json.load(sys.stdin); verify_credential(x['proof'],x['bundle'],b64decode(x['pin'],32),x['id'],hashlib.sha256(rfc8785.dumps(x['envelope'])).hexdigest()); print('verified')";
    const result=execFileSync(process.env.EVOTE_TEST_PYTHON ?? 'python',['-c',code],{cwd:fileURLToPath(new URL('../../../',import.meta.url)),input:JSON.stringify({proof,bundle:material.bundle,pin:material.pin,id:material.bundle.manifest.election_id,envelope:prepared.envelope}),encoding:'utf8'});
    expect(result.trim()).toBe('verified');
    expect(Object.keys(issuePayload(prepared.pending)).sort()).toEqual(['blinded_msg','election_id','request_id']);
  });
  it('encrypts the selected candidate with RSA-OAEP-SHA256 and AES-256-GCM bound to serial/election',async()=>{
    const raw=await crypto.subtle.decrypt({name:'RSA-OAEP'},material.tally.privateKey,unb64(prepared.envelope.encrypted_key));
    const aes=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);
    const aad=canonical({schema_version:1,election_id:proof.message.election_id,serial:proof.message.serial});
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(prepared.envelope.nonce),additionalData:aad,tagLength:128},aes,unb64(prepared.envelope.ciphertext));
    expect(JSON.parse(new TextDecoder().decode(plain))).toEqual({schema_version:1,election_id:proof.message.election_id,candidate_id:material.bundle.manifest.candidates[0]!.candidate_id});
  });
  it('rejects modified manifest and independent wrong authority key',async()=>{
    const changed=structuredClone(material.bundle);changed.manifest.candidates[0]!.candidate_name='Changed';
    await expect(verifyManifest(changed,material.pin,changed.manifest.election_id)).rejects.toThrow();
    await expect(verifyManifest(material.bundle,b64(new Uint8Array(32)),material.bundle.manifest.election_id)).rejects.toThrow();
  });
  it.each(['signature','serial','election_id','config_hash','envelope','prefix'] as const)('rejects modified %s',async change=>{
    const p=structuredClone(proof), envelope=structuredClone(prepared.envelope);
    if(change==='signature')p.signature=b64(new Uint8Array(384));
    else if(change==='envelope')envelope.ciphertext=b64(new Uint8Array(64));
    else if(change==='prefix')p.prepared_msg=b64(unb64(p.prepared_msg).slice(1));
    else p.message[change]=change==='serial' ? b64(new Uint8Array(32)) : change==='election_id' ? crypto.randomUUID() : '0'.repeat(64);
    await expect(verifyProof(p,envelope,material.bundle,material.pin)).rejects.toThrow();
  });
  it('rejects noncanonical encodings and unknown protocol fields',()=>{
    expect(()=>unb64(proof.signature+'=')).toThrow();
    expect(()=>unb64(proof.message.serial+'\n')).toThrow();
  });
  it('enforces the signed preparation window and rejects unknown candidates',async()=>{
    expect(windowStatus(material.bundle.manifest,Date.parse(material.bundle.manifest.closes_at))).toBe('closed');
    await expect(prepareBallot(material.bundle,material.pin,crypto.randomUUID())).rejects.toThrow();
  });
  it('rejects a genuinely signed wrong-salt profile rather than negotiating a downgrade',async()=>{
    // Negative construction only, matching the existing interoperability gate.
    const wrong=new BlindRSA({...RSABSSA.SHA384.PSS.Randomized().params,saltLength:0});
    const preparedMessage=wrong.prepare(messageBytes(proof.message));
    const {blindedMsg,inv}=await wrong.blind(material.ra.publicKey,preparedMessage);
    const blind=await wrong.blindSign(material.ra.privateKey,blindedMsg);
    const signature=await wrong.finalize(material.ra.publicKey,preparedMessage,blind,inv);
    await expect(verifyProof({...proof,prepared_msg:b64(preparedMessage),signature:b64(signature)},prepared.envelope,material.bundle,material.pin)).rejects.toThrow();
  });
  it('protects pending/final state with context-bound AEAD and rejects tampering/wrong passphrase',async()=>{
    const state:PrivateState={version:1,bundle:material.bundle,...prepared,proof,phase:'ready',receipt_hash:null};
    const pass='Synthetic recovery phrase only';
    const encrypted=await protect(state,pass,material.pin);
    expect(JSON.stringify(encrypted)).not.toContain(prepared.pending.inv);
    expect((await unlock(encrypted,pass,material.pin)).proof).toEqual(proof);
    await expect(unlock(encrypted,'Wrong recovery phrase only',material.pin)).rejects.toThrow();
    const changed=structuredClone(encrypted);changed.context.request_id=crypto.randomUUID();
    await expect(unlock(changed,pass,material.pin)).rejects.toThrow();
    expect(await receipt({election_id:proof.message.election_id,credential:proof,envelope:prepared.envelope})).toMatch(/^[0-9a-f]{64}$/);
  });
});

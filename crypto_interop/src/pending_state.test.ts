import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, basename, resolve } from 'node:path';
import { generateKeyPairSync, sign } from 'node:crypto';
import { b64, DOMAIN, messageBytes, MANIFEST_DOMAIN, MANIFEST_CONTEXT, PROFILE, manifestBytes, sha256 } from './protocol.js';
import { issuePayload, persistBeforeIssue, loadPending, preparePending, finalizePending } from './pending_state.js';

test('pending state is protected, recoverable, and never leaks into the RA request', async () => {
  const directory=await mkdtemp(join(tmpdir(),'evote-pending-test-'));
  try {
    const path=join(directory,'pending');
    const message={domain:DOMAIN,version:2,election_id:'11111111-1111-4111-8111-111111111111',
      serial:b64(Buffer.alloc(32,1)),envelope_hash:'a'.repeat(64),config_hash:'b'.repeat(64),key_id:'test-ra'};
    const state={version:1,request_id:'22222222-2222-4222-8222-222222222222',message,
      prepared_msg:b64(Buffer.concat([Buffer.alloc(32,2),messageBytes(message)])),
      blinded_msg:b64(Buffer.alloc(384,3)),inv:b64(Buffer.alloc(384,4)),key_fingerprint:'c'.repeat(64)};
    const passphrase='synthetic recovery test passphrase';
    const payload=await persistBeforeIssue(path,state,passphrase);
    assert.deepEqual(Object.keys(payload).sort(),['blinded_msg','election_id','request_id']);
    const contents=await readFile(path);
    for (const secret of [state.inv,message.serial,passphrase]) assert.equal(contents.includes(secret),false);
    assert.deepEqual(await loadPending(path,passphrase),state);
    assert.deepEqual(issuePayload(await loadPending(path,passphrase)),payload);
    await assert.rejects(persistBeforeIssue(path,state,passphrase));
    assert.deepEqual(await loadPending(path,passphrase),state);
    await assert.rejects(loadPending(path,'wrong synthetic passphrase'));
    const corrupted=JSON.parse(contents.toString()); corrupted.tag=b64(Buffer.alloc(16));
    await writeFile(path,JSON.stringify(corrupted));
    await assert.rejects(loadPending(path,passphrase));
  } finally {
    assert.equal(dirname(resolve(directory)),resolve(tmpdir()));
    assert.ok(basename(directory).startsWith('evote-pending-test-'));
    await rm(directory,{recursive:true,force:true});
  }
});

test('real Prepare/Blind persists the inverse and prefix before exposing the issue payload',async () => {
  const directory=await mkdtemp(join(tmpdir(),'evote-pending-test-'));
  try {
    const authority=generateKeyPairSync('ed25519');
    const entry=(key_id: string) => {
      const key=generateKeyPairSync('rsa',{modulusLength:3072,publicExponent:65537});
      const spki=key.publicKey.export({type:'spki',format:'der'});
      return {key_id,spki:b64(spki),fingerprint:sha256(spki)};
    };
    const election='11111111-1111-4111-8111-111111111111';
    const manifest={domain:MANIFEST_DOMAIN,version:1,election_id:election,
      opens_at:'2026-11-14T00:00:00Z',closes_at:'2026-11-15T00:00:00Z',
      candidates:[{candidate_id:'22222222-2222-4222-8222-222222222222',candidate_name:'Test'}],
      ra_key:entry('test-ra'),tally_key:entry('test-tally'),profile:PROFILE};
    const bundle={manifest,signature:b64(sign(null,Buffer.concat([MANIFEST_CONTEXT,manifestBytes(manifest)]),authority.privateKey))};
    const pin=authority.publicKey.export({format:'jwk'}).x!;
    const path=join(directory,'pending');
    const passphrase='synthetic protected test phrase';
    const request=await preparePending(path,passphrase,bundle,pin,election,'a'.repeat(64));
    const state=await loadPending(path,passphrase);
    assert.deepEqual(issuePayload(state),request);
    assert.equal(request.blinded_msg.length,512);
    assert.equal(Buffer.from((state as Record<string,string>).inv!,'base64url').length,384);
    await assert.rejects(preparePending(join(directory,'wrong'),passphrase,bundle,b64(Buffer.alloc(32)),election,'a'.repeat(64)));
    await assert.rejects(finalizePending(path,passphrase,b64(Buffer.alloc(384)),bundle,pin,election));
    assert.deepEqual(issuePayload(await loadPending(path,passphrase)),request);
  } finally {
    assert.equal(dirname(resolve(directory)),resolve(tmpdir()));
    assert.ok(basename(directory).startsWith('evote-pending-test-'));
    await rm(directory,{recursive:true,force:true});
  }
});

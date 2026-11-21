// Generated TEST keys and public evidence only. Never imported by production UI.
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { b64,canonical,finalize,prepareBallot,receipt,sha256,unb64 } from '../voting/crypto';
import { testMaterial } from '../voting/material.test-support';
import type { BoardPins,Evidence } from './verification';

export async function boardFixture() {
  const value=await testMaterial(),election=value.bundle.manifest.election_id;
  const pending=await prepareBallot(value.bundle,value.pin,value.bundle.manifest.candidates[0]!.candidate_id);
  const sig=await RSABSSA.SHA384.PSS.Randomized().blindSign(value.ra.privateKey,unb64(pending.pending.blinded_msg));
  const proof=await finalize(pending.pending,b64(sig),pending.envelope,value.bundle,value.pin);
  const record={election_id:election,serial:proof.message.serial,envelope:pending.envelope,prepared_msg:proof.prepared_msg,signature:proof.signature,
    receipt_hash:await receipt({election_id:election,envelope:pending.envelope,credential:proof})};
  const snapshotKey=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as CryptoKeyPair;
  const pubKey=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as CryptoKeyPair;
  const pins:BoardPins={authority:value.pin,evidence:b64(new Uint8Array(await crypto.subtle.exportKey('raw',snapshotKey.publicKey))),evidenceKeyId:'test-evidence',
    publication:b64(new Uint8Array(await crypto.subtle.exportKey('raw',pubKey.publicKey))),publicationKeyId:'test-publication'};
  const config=await sha256(canonical(value.bundle.manifest));
  const snapshot={schema_version:1,election_id:election,election_config_digest:config,ballots:[record]};
  const hash=await sha256(canonical(snapshot));
  const snapManifest={manifest_version:1,election_id:election,election_config_digest:config,snapshot_schema_version:1,snapshot_digest:hash,
    ballot_count:1,digest_algorithm:'SHA-256',signature_algorithm:'Ed25519',signing_key_id:pins.evidenceKeyId};
  async function sign(key:CryptoKey,context:string,object:unknown){const prefix=new TextEncoder().encode(context),raw=canonical(object),all=new Uint8Array(prefix.length+raw.length);all.set(prefix);all.set(raw,prefix.length);return b64(new Uint8Array(await crypto.subtle.sign('Ed25519',key,all)));}
  const report={report_version:1,election_id:election,election_config_digest:config,snapshot_digest:hash,algorithm_version:'evote-tally-v1',
    accepted_total:1,valid_total:1,invalid_total:0,counted_total:1,candidate_counts:[{candidate_id:value.bundle.manifest.candidates[0]!.candidate_id,vote_count:1}],
    invalid_reasons:{KEY_WRAP:0,AEAD:0,PLAINTEXT:0}};
  const reportHash=await sha256(canonical(report));
  const publication={manifest_version:1,election_id:election,election_config_digest:config,snapshot_digest:hash,tally_report_digest:reportHash,
    accepted_total:1,valid_total:1,invalid_total:0,counted_total:1,publication_key_id:pins.publicationKeyId,signature_algorithm:'Ed25519'};
  const bundle:Evidence={version:1,election_id:election,configuration:value.bundle,snapshot,
    snapshot_evidence:{manifest:snapManifest,signature:await sign(snapshotKey.privateKey,'EVOTE-SNAPSHOT-v1\0',snapManifest)},
    tally:{report,report_digest:reportHash,signature:await sign(snapshotKey.privateKey,'EVOTE-TALLY-REPORT-v1\0',report),signing_key_id:pins.evidenceKeyId},
    publication:{manifest:publication,signature:await sign(pubKey.privateKey,'EVOTE-RESULTS-v1\0',publication)}};
  return {bundle,pins,election,hash:record.receipt_hash,sign,snapshotKey,pubKey};
}

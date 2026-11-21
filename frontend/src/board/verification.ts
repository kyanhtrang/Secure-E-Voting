// Offline public verification: no fetch, authentication, private keys or decryption.
import { b64,canonical,fields,requireValid,sha256,unb64,uuid,verifyManifest,verifyProof,receipt,
  type Ballot,type Bundle,type Envelope,type Proof } from '../voting/crypto';

export interface BoardPins { authority:string; evidence:string; evidenceKeyId:string; publication:string; publicationKeyId:string }
export interface Report { report_version:number; election_id:string; election_config_digest:string; snapshot_digest:string;
  algorithm_version:string; accepted_total:number; valid_total:number; invalid_total:number; counted_total:number;
  candidate_counts:{candidate_id:string;vote_count:number}[]; invalid_reasons:{KEY_WRAP:number;AEAD:number;PLAINTEXT:number} }
export interface RecordEntry { election_id:string; serial:string; envelope:Envelope; prepared_msg:string; signature:string; receipt_hash:string }
export interface Evidence { version:number;election_id:string;configuration:Bundle;
  snapshot:{schema_version:number;election_id:string;election_config_digest:string;ballots:RecordEntry[]};
  snapshot_evidence:{manifest:unknown;signature:string};
  tally:{report:Report;report_digest:string;signature:string;signing_key_id:string};publication:{manifest:unknown;signature:string} }
export type Verification='VERIFIED'|'NOT_FOUND'|'INVALID'|'UNVERIFIED'|'UNAVAILABLE';
export class Unverified extends Error { constructor(){super('Independent trust pins are required.');} }
function checkHash(value:unknown) { requireValid(typeof value==='string' && /^[0-9a-f]{64}$/.test(value)); }
function same(a:unknown,b:unknown) { requireValid(b64(canonical(a))===b64(canonical(b))); }
async function signed(pin:string,context:string,value:unknown,signature:string) {
  const key=await crypto.subtle.importKey('raw',unb64(pin,32),'Ed25519',false,['verify']);
  const raw=canonical(value),prefix=new TextEncoder().encode(context),bytes=new Uint8Array(prefix.length+raw.length);
  bytes.set(prefix);bytes.set(raw,prefix.length);
  requireValid(await crypto.subtle.verify('Ed25519',key,unb64(signature,64),bytes));
}
export async function verifyEvidence(value:unknown,election:string,pins:BoardPins):Promise<Evidence> {
  try {
    for(const key of [pins.authority,pins.evidence,pins.publication])unb64(key,32);
    requireValid(new Set([pins.authority,pins.evidence,pins.publication]).size===3);
    for(const id of [pins.evidenceKeyId,pins.publicationKeyId])requireValid(/^[a-z0-9][a-z0-9._-]{0,127}$/.test(id));
  } catch { throw new Unverified(); }
  uuid(election);
  fields(value,['version','election_id','configuration','snapshot','snapshot_evidence','tally','publication']);
  requireValid(value.version===1 && value.election_id===election && canonical(value).length<=16777216);
  const bundle=value as unknown as Evidence;
  await verifyManifest(bundle.configuration,pins.authority,election);
  const config=await sha256(canonical(bundle.configuration.manifest));
  const snap=bundle.snapshot;fields(snap,['schema_version','election_id','election_config_digest','ballots']);
  requireValid(snap.schema_version===1 && snap.election_id===election && snap.election_config_digest===config);
  requireValid(Array.isArray(snap.ballots) && snap.ballots.length<=1000);
  const hashes:string[]=[],serials:string[]=[];
  for(const row of snap.ballots) {
    fields(row,['election_id','serial','envelope','prepared_msg','signature','receipt_hash']);
    requireValid(row.election_id===election);unb64(row.serial,32);checkHash(row.receipt_hash);
    const prepared=unb64(row.prepared_msg);requireValid(prepared.length>32);
    const message:unknown=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(prepared.slice(32)));
    fields(message,['domain','version','election_id','serial','envelope_hash','config_hash','key_id']);
    requireValid(message.serial===row.serial);
    const proof={message,prepared_msg:row.prepared_msg,signature:row.signature} as unknown as Proof;
    await verifyProof(proof,row.envelope,bundle.configuration,pins.authority);
    requireValid(await receipt({election_id:election,credential:proof,envelope:row.envelope} satisfies Ballot)===row.receipt_hash);
    hashes.push(row.receipt_hash);serials.push(row.serial);
  }
  same(hashes,[...new Set(hashes)].sort());requireValid(new Set(serials).size===serials.length);
  const snapshotHash=await sha256(canonical(snap));
  fields(bundle.snapshot_evidence,['manifest','signature']);
  const expected={manifest_version:1,election_id:election,election_config_digest:config,snapshot_schema_version:1,
    snapshot_digest:snapshotHash,ballot_count:snap.ballots.length,digest_algorithm:'SHA-256',signature_algorithm:'Ed25519',signing_key_id:pins.evidenceKeyId};
  same(bundle.snapshot_evidence.manifest,expected);
  await signed(pins.evidence,'EVOTE-SNAPSHOT-v1\0',expected,bundle.snapshot_evidence.signature);
  const tally=bundle.tally;fields(tally,['report','report_digest','signature','signing_key_id']);
  requireValid(tally.signing_key_id===pins.evidenceKeyId && await sha256(canonical(tally.report))===tally.report_digest);
  await signed(pins.evidence,'EVOTE-TALLY-REPORT-v1\0',tally.report,tally.signature);
  const r=tally.report;
  fields(r,['report_version','election_id','election_config_digest','snapshot_digest','algorithm_version','accepted_total','valid_total','invalid_total','counted_total','candidate_counts','invalid_reasons']);
  requireValid(r.report_version===1 && r.algorithm_version==='evote-tally-v1' && r.election_id===election
    && r.election_config_digest===config && r.snapshot_digest===snapshotHash);
  for(const n of [r.accepted_total,r.valid_total,r.invalid_total,r.counted_total])requireValid(Number.isSafeInteger(n) && n>=0 && n<=1000);
  requireValid(r.accepted_total===snap.ballots.length && r.accepted_total===r.valid_total+r.invalid_total && r.counted_total===r.valid_total);
  requireValid(Array.isArray(r.candidate_counts));
  same(r.candidate_counts.map(c=>c.candidate_id),bundle.configuration.manifest.candidates.map(c=>c.candidate_id));
  for(const c of r.candidate_counts){fields(c,['candidate_id','vote_count']);requireValid(Number.isSafeInteger(c.vote_count) && c.vote_count>=0);}
  fields(r.invalid_reasons,['KEY_WRAP','AEAD','PLAINTEXT']);
  requireValid(Object.values(r.invalid_reasons).every(n=>Number.isSafeInteger(n)&&n>=0)
    && Object.values(r.invalid_reasons).reduce((a,b)=>a+b,0)===r.invalid_total
    && r.candidate_counts.reduce((a,b)=>a+b.vote_count,0)===r.counted_total);
  const pub={manifest_version:1,election_id:election,election_config_digest:config,snapshot_digest:snapshotHash,
    tally_report_digest:tally.report_digest,accepted_total:r.accepted_total,valid_total:r.valid_total,invalid_total:r.invalid_total,
    counted_total:r.counted_total,publication_key_id:pins.publicationKeyId,signature_algorithm:'Ed25519'};
  fields(bundle.publication,['manifest','signature']);same(bundle.publication.manifest,pub);
  await signed(pins.publication,'EVOTE-RESULTS-v1\0',pub,bundle.publication.signature);
  return bundle;
}

export function inclusion(bundle:Evidence,hash:string):'VERIFIED'|'NOT_FOUND' {
  checkHash(hash);return bundle.snapshot.ballots.some(row=>row.receipt_hash===hash)?'VERIFIED':'NOT_FOUND';
}

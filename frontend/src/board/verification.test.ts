// @vitest-environment node
import { beforeAll,expect,it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { boardFixture } from './fixtures.test-support';
import { inclusion,Unverified,verifyEvidence } from './verification';
import { canonical,sha256 } from '../voting/crypto';

let value:Awaited<ReturnType<typeof boardFixture>>;
beforeAll(async()=>{value=await boardFixture();},20000);
it('independently verifies the complete signature/credential/receipt chain',async()=>{
  const verified=await verifyEvidence(value.bundle,value.election,value.pins);
  expect(inclusion(verified,value.hash)).toBe('VERIFIED');expect(inclusion(verified,'0'.repeat(64))).toBe('NOT_FOUND');
});
it('matches the offline Python verifier without sharing implementation',()=>{
  const script="import sys,json;from backend.board.verification import Trust,verify;from backend.crypto.credential_protocol import b64decode;x=json.load(sys.stdin);p=x['pins'];verify(x['bundle'],x['election'],Trust(b64decode(p['authority'],32),b64decode(p['evidence'],32),p['evidenceKeyId'],b64decode(p['publication'],32),p['publicationKeyId']));print('VERIFIED')";
  const result=execFileSync(process.env.EVOTE_TEST_PYTHON??'python',['-c',script],{cwd:fileURLToPath(new URL('../../../',import.meta.url)),
    input:JSON.stringify({bundle:value.bundle,election:value.election,pins:value.pins}),encoding:'utf8'});
  expect(result.trim()).toBe('VERIFIED');
});
it.each(['configuration','snapshot_evidence','tally','publication'] as const)('rejects changed %s signature',async field=>{
  const bad=structuredClone(value.bundle);bad[field].signature='A'.repeat(86);
  await expect(verifyEvidence(bad,value.election,value.pins)).rejects.toThrow();
});
it.each(['election','serial','ciphertext','counts','unknown','missing'] as const)('rejects %s inconsistency',async change=>{
  const bad=structuredClone(value.bundle);
  if(change==='election')bad.election_id=crypto.randomUUID();
  if(change==='serial')bad.snapshot.ballots[0]!.serial='A'.repeat(43);
  if(change==='ciphertext')bad.snapshot.ballots[0]!.envelope.ciphertext='A'.repeat(100);
  if(change==='counts')bad.tally.report.valid_total=0;
  if(change==='unknown')Object.assign(bad,{voter_id:'rejected'});
  if(change==='missing')bad.snapshot.ballots=[];
  await expect(verifyEvidence(bad,value.election,value.pins)).rejects.toThrow();
});
it('does not trust a missing or substituted public anchor',async()=>{
  await expect(verifyEvidence(value.bundle,value.election,{...value.pins,evidence:''})).rejects.toBeInstanceOf(Unverified);
  await expect(verifyEvidence(value.bundle,value.election,{...value.pins,authority:'A'.repeat(43)})).rejects.toThrow();
});
it('rejects wrong counts even with authentic test-authority signatures',async()=>{
  const bad=structuredClone(value.bundle);bad.tally.report.accepted_total=2;
  bad.tally.report_digest=await sha256(canonical(bad.tally.report));
  bad.tally.signature=await value.sign(value.snapshotKey.privateKey,'EVOTE-TALLY-REPORT-v1\0',bad.tally.report);
  bad.publication.manifest={...(bad.publication.manifest as object),accepted_total:2,tally_report_digest:bad.tally.report_digest};
  bad.publication.signature=await value.sign(value.pubKey.privateKey,'EVOTE-RESULTS-v1\0',bad.publication.manifest);
  await expect(verifyEvidence(bad,value.election,value.pins)).rejects.toThrow();
});

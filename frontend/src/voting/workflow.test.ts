// @vitest-environment node
import { beforeAll, expect, it, vi } from 'vitest';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { b64, receipt, unb64, type Ballot } from './crypto';
import { testMaterial } from './material.test-support';
import { anonymousClient, FlowError } from './api';
import { VotingWorkflow } from './workflow';
import { type ProtectedState, type RecoveryStore } from './recovery';

let material:Awaited<ReturnType<typeof testMaterial>>;
beforeAll(async()=>{material=await testMaterial();});
function store():RecoveryStore { const rows=new Map<string,ProtectedState>();return {list:async()=>[...rows.values()],save:async(blob,create)=>{if(create && rows.has(blob.context.election_id))throw new Error('existing');rows.set(blob.context.election_id,structuredClone(blob));}}; }
const pass='Synthetic browser recovery phrase';
async function ready(flow:VotingWorkflow) {
  await flow.prepare(material.bundle,material.bundle.manifest.candidates[0]!.candidate_id,pass);
  await flow.issue(async payload=>({status:'issued',ra_key_id:'test-ra',profile:material.bundle.manifest.profile,blind_sig:b64(await RSABSSA.SHA384.PSS.Randomized().blindSign(material.ra.privateKey,unb64(payload.blinded_msg)))}));
  expect(flow.state?.phase).toBe('ready');
}
it('commits protected pending before issuance; signing failure retries exact request and double-clicks do not issue twice',async()=>{
  const persistence=store(), flow=new VotingWorkflow(material.pin,persistence,anonymousClient(false));
  await flow.prepare(material.bundle,material.bundle.manifest.candidates[0]!.candidate_id,pass);
  const first=structuredClone(flow.state!.pending);
  const failed=vi.fn(async()=>{expect((await persistence.list())).toHaveLength(1);throw new FlowError('unavailable');});
  await Promise.all([flow.issue(failed),flow.issue(failed)]);expect(failed).toHaveBeenCalledTimes(1);
  expect(flow.state!.pending).toEqual(first);
  await flow.issue(async payload=>{expect(payload).toEqual({election_id:first.message.election_id,request_id:first.request_id,blinded_msg:first.blinded_msg});return {status:'replayed',ra_key_id:'test-ra',profile:material.bundle.manifest.profile,blind_sig:b64(await RSABSSA.SHA384.PSS.Randomized().blindSign(material.ra.privateKey,unb64(payload.blinded_msg)))};});
  expect(flow.state?.phase).toBe('ready');
});
it('sends no identity, token, issuance metadata or cookies to Voting and recovers uncertain commits',async()=>{
  let flow:VotingWorkflow;
  const calls:RequestInit[]=[];
  const transport=vi.fn<typeof fetch>().mockImplementation(async(url,options)=>{
    calls.push(options!);expect(flow.state?.phase).toBe('submission_unknown');
    const ballot=JSON.parse(String(options!.body)) as Ballot;
    expect(Object.keys(ballot).sort()).toEqual(['credential','election_id','envelope']);
    expect(options?.credentials).toBe('omit');expect(options?.headers).not.toHaveProperty('Authorization');
    expect(String(options!.body)).not.toContain('request_id');expect(String(options!.body)).not.toContain('voter_id');
    if(!String(url).endsWith('/receipt'))throw new TypeError('SYNTHETIC_SECRET_NETWORK_ERROR');
    return new Response(JSON.stringify({status:'accepted',receipt_hash:await receipt(ballot)}),{status:200});
  });
  flow=new VotingWorkflow(material.pin,store(),anonymousClient(true,transport));await ready(flow);
  const pending=structuredClone(flow.state!.pending);
  await Promise.all([flow.send(),flow.send()]);expect(transport).toHaveBeenCalledTimes(1);
  expect(flow.state?.phase).toBe('submission_unknown');expect(flow.message).not.toContain('SYNTHETIC_SECRET');
  await flow.send(true);expect(flow.state?.phase).toBe('accepted');expect(flow.state!.pending).toEqual(pending);expect(calls).toHaveLength(2);
});
it('rejects a mismatched receipt and preserves the same protected credential',async()=>{
  const transport=vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({status:'accepted',receipt_hash:'0'.repeat(64)}),{status:201}));
  const flow=new VotingWorkflow(material.pin,store(),anonymousClient(true,transport));await ready(flow);await flow.send();
  expect(flow.state?.phase).toBe('submission_unknown');expect(flow.state?.receipt_hash).toBeNull();
});
it('does not contact RA if durable storage fails and will not replace an existing election request',async()=>{
  const flow=new VotingWorkflow(material.pin,{list:async()=>[],save:async()=>{throw new Error('disk');}},anonymousClient(false));
  await flow.prepare(material.bundle,material.bundle.manifest.candidates[0]!.candidate_id,pass);
  expect(flow.state).toBeNull();const issue=vi.fn();await flow.issue(issue);expect(issue).not.toHaveBeenCalled();
  const persistence=store(), one=new VotingWorkflow(material.pin,persistence,anonymousClient(false));await one.prepare(material.bundle,material.bundle.manifest.candidates[0]!.candidate_id,pass);
  const two=new VotingWorkflow(material.pin,persistence,anonymousClient(false));await two.prepare(material.bundle,material.bundle.manifest.candidates[0]!.candidate_id,pass);expect(two.state).toBeNull();
});
it.each([409,422,503])('preserves the request following HTTP %s',async status=>{
  const flow=new VotingWorkflow(material.pin,store(),anonymousClient(true,vi.fn<typeof fetch>().mockResolvedValue(new Response('',{status}))));await ready(flow);
  const serial=flow.state!.pending.message.serial;await flow.send();expect(flow.state?.phase).toBe('submission_unknown');expect(flow.state!.pending.message.serial).toBe(serial);
});
it('unlocks the original encrypted record after memory is discarded',async()=>{
  const persistence=store(), first=new VotingWorkflow(material.pin,persistence,anonymousClient(false));await ready(first);
  const original=structuredClone(first.state), blob=first.protectedState;first.forgetMemory();expect(first.state).toBeNull();
  await first.restore(blob,pass);expect(first.state).toEqual(original);
});
it('blocks preparation and new submission after the signed deadline but still permits exact receipt recovery',async()=>{
  const transport=vi.fn<typeof fetch>().mockImplementation(async(url,options)=>{
    expect(String(url)).toBe('/api/v1/vote/ballots/receipt');
    return new Response(JSON.stringify({status:'accepted',receipt_hash:await receipt(JSON.parse(String(options?.body)) as Ballot)}),{status:200});
  });
  const flow=new VotingWorkflow(material.pin,store(),anonymousClient(true,transport));await ready(flow);
  const serial=flow.state!.pending.message.serial;
  const clock=vi.spyOn(Date,'now').mockReturnValue(Date.parse(material.bundle.manifest.closes_at));
  try {
    const late=new VotingWorkflow(material.pin,store(),anonymousClient(false));
    await late.prepare(material.bundle,material.bundle.manifest.candidates[0]!.candidate_id,pass);
    expect(late.state).toBeNull();
    await flow.send();expect(transport).not.toHaveBeenCalled();expect(flow.state?.phase).toBe('ready');
    await flow.send(true);expect(flow.state?.phase).toBe('accepted');expect(flow.state!.pending.message.serial).toBe(serial);
  } finally { clock.mockRestore(); }
});

import { fields, finalize, issuePayload, prepareBallot, receipt, requireValid, verifyProof, windowStatus, type Ballot, type Bundle } from './crypto';
import { anonymousClient, FlowError, flowMessage } from './api';
import { protect, unlock, type PrivateState, type ProtectedState, type RecoveryStore } from './recovery';

export class VotingWorkflow {
  state: PrivateState | null=null;
  protectedState: ProtectedState | null=null;
  busy=false;
  message='';
  private passphrase='';
  private listeners=new Set<()=>void>();
  readonly pin: string;
  readonly store: RecoveryStore;
  private anonymous: ReturnType<typeof anonymousClient>;
  constructor(pin: string, store: RecoveryStore, anonymous: ReturnType<typeof anonymousClient>) { this.pin=pin;this.store=store;this.anonymous=anonymous; }
  subscribe(listener: ()=>void) { this.listeners.add(listener); return ()=>{this.listeners.delete(listener);}; }
  private emit() { for (const listener of this.listeners) listener(); }
  private async run(action: ()=>Promise<void>) {
    if (this.busy) return;
    this.busy=true; this.message=''; this.emit();
    try { await action(); } catch (error) { if (!this.state) this.passphrase=''; this.message=flowMessage(error); }
    finally { this.busy=false; this.emit(); }
  }
  private async persist(state: PrivateState, create=false) {
    const blob=await protect(state,this.passphrase,this.pin);
    await this.store.save(blob,create); // IDB transaction COMPLETE, not just request success.
    this.state=state; this.protectedState=blob;
  }
  prepare(bundle: Bundle,candidate: string,passphrase: string) { return this.run(async()=>{
    requireValid(this.state === null);
    const existing=await this.store.list();
    if (existing.some(blob=>blob.context.election_id === bundle.manifest.election_id)) throw new FlowError('reserved');
    this.passphrase=passphrase;
    const {pending,envelope}=await prepareBallot(bundle,this.pin,candidate);
    await this.persist({version:1,bundle,envelope,pending,proof:null,phase:'pending',receipt_hash:null},true);
  }); }
  restore(blob: unknown,passphrase: string) { return this.run(async()=>{
    requireValid(this.state === null);
    const state=await unlock(blob,passphrase,this.pin);
    const existing=await this.store.list();
    requireValid(!existing.some(value=>value.context.election_id === state.pending.message.election_id && value.context.request_id !== state.pending.request_id));
    this.passphrase=passphrase; await this.persist(state);
  }); }
  issue(send: (payload: ReturnType<typeof issuePayload>)=>Promise<unknown>) { return this.run(async()=>{
    const state=this.state; requireValid(state && state.phase === 'pending');
    const result=await send(issuePayload(state.pending));
    fields(result,['status','ra_key_id','profile','blind_sig']);
    requireValid((result.status === 'issued' || result.status === 'replayed') && result.ra_key_id === state.bundle.manifest.ra_key.key_id && result.profile === state.bundle.manifest.profile && typeof result.blind_sig === 'string');
    const proof=await finalize(state.pending,result.blind_sig,state.envelope,state.bundle,this.pin);
    await this.persist({...state,proof,phase:'ready'});
  }); }
  send(recover=false) { return this.run(async()=>{
    const initial=this.state; requireValid(initial && initial.proof && initial.phase !== 'accepted');
    if (!recover && windowStatus(initial.bundle.manifest) !== 'open') throw new FlowError('conflict');
    await verifyProof(initial.proof,initial.envelope,initial.bundle,this.pin);
    const ballot: Ballot={election_id:initial.pending.message.election_id,credential:initial.proof,envelope:initial.envelope};
    if (!recover) await this.persist({...initial,phase:'submission_unknown'}); // Crash-safe BEFORE HTTP.
    const expected=await receipt(ballot);
    const received=await (recover ? this.anonymous.recover(ballot) : this.anonymous.submit(ballot));
    requireValid(received === expected);
    await this.persist({...initial,phase:'accepted',receipt_hash:received});
  }); }
  forgetMemory() { if (this.busy) return; this.state=null; this.protectedState=null; this.passphrase=''; this.message=''; this.emit(); }
}

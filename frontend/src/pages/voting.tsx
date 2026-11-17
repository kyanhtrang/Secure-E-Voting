import { useEffect, useState, type FormEvent } from 'react';
import { useParams } from 'react-router';
import { CalendarDays, CheckCircle2, Download, KeyRound, LockKeyhole, RefreshCw, ShieldCheck } from 'lucide-react';
import { useSession } from '../auth/session';
import { ApiError, safeError } from '../api/auth';
import { Badge, Banner, BoundaryNote, Button, EmptyState, Loading, PageHeading, Panel, TextLink } from '../components/ui';
import { fields, requireValid, uuid, verifyManifest, windowStatus, type Bundle } from '../voting/crypto';
import { configured, useVoting } from '../voting/context';
import { flowMessage } from '../voting/api';
import { parseProtectedFile, protectedFile, type ProtectedState } from '../voting/recovery';

interface Election { election_id:string; bundle:Bundle }
function useCatalogue() {
  const session=useSession(), workflow=useVoting();
  const [rows,setRows]=useState<Election[] | null>(null), [error,setError]=useState(''), [generation,reload]=useState(0);
  useEffect(()=>{
    let active=true;
    if (!configured(workflow.pin)) { setError('Voting needs an independently configured manifest authority public key.'); return; }
    setRows(null); setError('');
    void (async()=>{
      try {
        const data=await session.elections(); fields(data,['elections']);
        requireValid(Array.isArray(data.elections) && data.elections.length <= 100);
        const entries=await Promise.all(data.elections.map(async(value: unknown)=>{
          fields(value,['election_id','bundle','eligibility','credential_availability']); uuid(value.election_id);
          requireValid(value.eligibility === 'checked_on_issue' && value.credential_availability === 'checked_on_issue');
          return {election_id:value.election_id,bundle:await verifyManifest(value.bundle,workflow.pin,value.election_id)};
        }));
        requireValid(new Set(entries.map(entry=>entry.election_id)).size === entries.length);
        if (active) setRows(entries);
      } catch (value) { if (active) setError(value instanceof ApiError ? safeError(value) : flowMessage(value)); }
    })();
    return ()=>{active=false;};
  },[session.elections,workflow.pin,generation]);
  return {rows,error,reload:()=>reload(value=>value+1)};
}
function Progress({step}: {step:number}) {
  return <ol className="vote-progress" aria-label="Voting progress">{['Choose','Protect','Authorize','Submit','Receipt'].map((label,index)=><li key={label} aria-current={step === index ? 'step' : undefined} className={index <= step ? 'active' : ''}><span>{index < step ? <CheckCircle2 size={16} /> : index+1}</span>{label}</li>)}</ol>;
}
function Window({bundle}: {bundle:Bundle}) {
  return <><Badge tone={windowStatus(bundle.manifest) === 'open' ? 'success' : 'amber'}>Signed window: {windowStatus(bundle.manifest)}</Badge><dl className="vote-facts"><div><dt>Opens</dt><dd>{new Date(bundle.manifest.opens_at).toLocaleString()}</dd></div><div><dt>Closes</dt><dd>{new Date(bundle.manifest.closes_at).toLocaleString()}</dd></div><div><dt>Eligibility</dt><dd>Checked by RA on issuance</dd></div><div><dt>Live status</dt><dd>Voting checks its database on submission</dd></div></dl></>;
}
export function VotingElections() {
  const {rows,error,reload}=useCatalogue();
  return <><PageHeading eyebrow="VERIFIED ELECTION ACCESS" title="Find your election" description="Election configurations are verified with your independently pinned authority key." />
    <Panel title="Election catalogue" description="Only explicitly published, signed RA policies appear here.">
      {error ? <div className="vote-pad"><Banner tone="error">{error}</Banner><Button secondary onClick={reload}>Retry catalogue</Button></div> : rows === null ? <Loading>Verifying election configurations…</Loading> : !rows.length ? <EmptyState icon={CalendarDays} title="No elections have been published">The operator has not published any existing election policy to this local catalogue.</EmptyState> : <div className="election-cards">{rows.map(row=><article className="election-card" key={row.election_id}><ShieldCheck size={24} aria-hidden="true" /><h3>Election {row.election_id.slice(0,8)}</h3><p className="mono">{row.election_id}</p><Window bundle={row.bundle} /><p>{row.bundle.manifest.candidates.length} verified candidates</p><TextLink to={'/voter/elections/'+row.election_id}>View candidates & participation</TextLink></article>)}</div>}
    </Panel><BoundaryNote>Catalogue access is not an eligibility decision or proof of issuance availability. The RA checks eligibility and its database clock when you request the credential.</BoundaryNote></>;
}
export function VotingElectionDetail() {
  const {electionId}=useParams(), {rows,error,reload}=useCatalogue(), workflow=useVoting();
  const [candidate,setCandidate]=useState(''), [confirmed,setConfirmed]=useState(false);
  const entry=rows?.find(row=>row.election_id === electionId);
  const prepare=(event:FormEvent<HTMLFormElement>)=>{event.preventDefault(); if (!entry || !confirmed) return; const form=event.currentTarget, pass=String(new FormData(form).get('recovery-passphrase') ?? ''); (form.elements.namedItem('recovery-passphrase') as HTMLInputElement).value=''; void workflow.prepare(entry.bundle,candidate,pass);};
  return <><TextLink to="/voter/elections">Back to elections</TextLink><PageHeading eyebrow="SIGNED ELECTION CONFIGURATION" title={entry ? 'Election '+entry.election_id.slice(0,8) : 'Election details'} description="Choose from the verified candidate catalogue. Nothing is sent to RA until protected preparation completes." />
    <Progress step={workflow.state ? workflow.state.proof ? 3 : 2 : 0} />
    {error ? <><Banner tone="error">{error}</Banner><Button secondary onClick={reload}>Retry catalogue</Button></> : rows === null ? <Loading>Verifying election…</Loading> : !entry ? <EmptyState title="No verified election metadata">This election was not found in the explicitly published catalogue.</EmptyState> : <>
      <Panel title="Voting window & policy"><div className="vote-pad"><Window bundle={entry.bundle} /><p className="fine-print">Key: {entry.bundle.manifest.ra_key.key_id} · RSA-3072 · RFC 9474</p></div></Panel>
      {workflow.message && <Banner tone="error">{workflow.message}</Banner>}
      {workflow.state ? <Panel title="An existing request is protected"><div className="vote-pad"><p>Continue your original request. Generating another serial is blocked.</p><TextLink to="/voter/credentials">Open credential & recovery</TextLink></div></Panel> : <Panel title="Your candidate" description="Confirm the choice before it is encrypted. It cannot be displayed from a recovery file.">
        <form className="vote-pad" onSubmit={prepare}><fieldset disabled={workflow.busy || windowStatus(entry.bundle.manifest) !== 'open'}><legend>Select one candidate</legend><div className="candidate-options">{entry.bundle.manifest.candidates.map(value=><label className={'candidate-option '+(candidate === value.candidate_id ? 'selected' : '')} key={value.candidate_id}><input type="radio" name="candidate" value={value.candidate_id} checked={candidate === value.candidate_id} onChange={()=>{setCandidate(value.candidate_id);setConfirmed(false);}} required /><strong>{value.candidate_name}</strong><small className="mono">{value.candidate_id}</small></label>)}</div>
          <label className="check-field"><input type="checkbox" checked={confirmed} onChange={event=>setConfirmed(event.target.checked)} required />I confirm this candidate. Preparing locks this request and encrypted choice.</label>
          <div className="field"><label htmlFor="recovery-passphrase">Recovery passphrase</label><input id="recovery-passphrase" name="recovery-passphrase" type="password" autoComplete="new-password" minLength={16} maxLength={1024} required /><small>Use at least 16 characters. Keep it separately from your encrypted recovery file. It is never sent to a server.</small></div>
          <Button type="submit" disabled={!candidate || !confirmed || workflow.busy} busy={workflow.busy}>Protect & prepare credential</Button></fieldset>
          {windowStatus(entry.bundle.manifest) !== 'open' && <Banner tone="warning">This election is {windowStatus(entry.bundle.manifest)}. New preparation is disabled.</Banner>}
          {workflow.state && <TextLink to="/voter/credentials">Continue to authorization</TextLink>}
        </form></Panel>}
    </>}
    <BoundaryNote>Only the encrypted envelope hash enters the blinded v2 message. The serial, candidate and finalized credential are never sent to RA. Encrypted candidate validity is checked later by Tally.</BoundaryNote></>;
}
function download(name:string,contents:string) { const url=URL.createObjectURL(new Blob([contents],{type:'application/json'})); const anchor=document.createElement('a'); anchor.href=url;anchor.download=name;anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000); }
function Backup() {
  const workflow=useVoting();
  return workflow.protectedState ? <><Button secondary disabled={workflow.busy} onClick={()=>download('evote-recovery-'+workflow.protectedState!.context.election_id+'.json',protectedFile(workflow.protectedState!))}><Download size={16} />Save encrypted recovery file</Button><Button secondary disabled={workflow.busy} onClick={()=>workflow.forgetMemory()}>Lock private state</Button></> : null;
}
function Restore() {
  const workflow=useVoting(), [stored,setStored]=useState<ProtectedState[]>([]), [selected,setSelected]=useState(''), [file,setFile]=useState<unknown>(null), [message,setMessage]=useState('');
  useEffect(()=>{let active=true;void workflow.store.list().then(rows=>{if(active)setStored(rows.filter(row=>typeof row?.context?.election_id === 'string'));}).catch(()=>{if(active)setMessage('Protected browser storage is unavailable. Use your encrypted recovery file.');});return()=>{active=false;};},[workflow]);
  const restore=(event:FormEvent<HTMLFormElement>)=>{event.preventDefault();const form=event.currentTarget, pass=String(new FormData(form).get('unlock-passphrase') ?? '');(form.elements.namedItem('unlock-passphrase') as HTMLInputElement).value='';const blob=file ?? stored.find(row=>row.context.election_id === selected);if(blob)void workflow.restore(blob,pass);};
  return <Panel title="Restore your original request" description="Use the original RA account for issuance recovery. A lost passphrase or file cannot reset eligibility."><form onSubmit={restore} className="vote-pad">
    {message && <Banner tone="warning">{message}</Banner>}
    <div className="field"><label htmlFor="stored-recovery">Protected browser record</label><select id="stored-recovery" value={selected} onChange={event=>{setSelected(event.target.value);setFile(null);}}><option value="">Choose a saved election</option>{stored.map(row=><option key={row.context.election_id} value={row.context.election_id}>{row.context.election_id}</option>)}</select></div>
    <div className="field"><label htmlFor="recovery-file">Or import an encrypted recovery file</label><input id="recovery-file" type="file" accept="application/json,.json" onChange={event=>{const uploaded=event.target.files?.[0];setFile(null); if(uploaded)void(async()=>{try{if(uploaded.size > 524288)throw new Error();setFile(parseProtectedFile(await uploaded.text()));setMessage('Encrypted file loaded. Enter its passphrase to verify and unlock.');}catch{setMessage('The recovery file could not be read.');}})();}} /></div>
    <div className="field"><label htmlFor="unlock-passphrase">Recovery passphrase</label><input id="unlock-passphrase" name="unlock-passphrase" type="password" autoComplete="off" minLength={16} maxLength={1024} required /></div>
    <Button disabled={workflow.busy || (!file && !selected)} busy={workflow.busy}>Verify & unlock recovery</Button>
  </form></Panel>;
}
export function VotingCredentials() {
  const workflow=useVoting(), session=useSession(), state=workflow.state;
  return <><PageHeading eyebrow="BLIND CREDENTIAL & RECOVERY" title="Protect your private participation" description="The browser prepares and unblinds. The RA sees only election ID, request ID and blinded bytes." /><Progress step={state ? state.proof ? 3 : 2 : 0} />
    {workflow.message && <Banner tone="error">{workflow.message}</Banner>}
    {!configured(workflow.pin) ? <Banner tone="warning">Configure the independent manifest authority public key before voting.</Banner> : !state ? <><Panel title="Start with a verified election"><div className="vote-pad"><TextLink to="/voter/elections">Choose an election</TextLink></div></Panel><Restore /></> : <Panel title={state.proof ? 'Credential verified locally' : 'Protected request ready for RA'} action={<Badge tone={state.proof ? 'success' : 'amber'}>{state.phase}</Badge>}><div className="vote-pad"><p className="mono">Election {state.pending.message.election_id}</p><p>{state.proof ? 'Your finalized credential is bound to this encrypted envelope. Continue without RA authentication on the anonymous route.' : 'Protected state was committed before any issuance request. A retry uses exactly the same request ID and blinded bytes.'}</p><div className="inline-actions"><Backup />{!state.proof ? <Button busy={workflow.busy} disabled={workflow.busy} onClick={()=>void workflow.issue(session.issue)}><KeyRound size={16} />Request / recover same credential</Button> : <TextLink to="/vote">Continue to anonymous voting</TextLink>}</div><p className="fine-print">Download a backup now. Keep its passphrase separately. Do not share either file or browser profile.</p></div></Panel>}
    <BoundaryNote>One authorization per voter and election is enforced by PostgreSQL. This UI cannot reset it. No plaintext candidate or finalized credential is sent to RA.</BoundaryNote></>;
}
export function VotingBallot() {
  const workflow=useVoting(), state=workflow.state, [confirmed,setConfirmed]=useState(false), [copyMessage,setCopyMessage]=useState('');
  return <><PageHeading eyebrow="ANONYMOUS VOTING" title={state?.phase === 'accepted' ? 'Your ballot was accepted.' : 'Submit your sealed ballot'} description="This route uses a separate client with no RA bearer token, identity cookies or authenticated interceptor." /><Progress step={state?.phase === 'accepted' ? 4 : 3} />
    {workflow.message && <Banner tone="error">{workflow.message}</Banner>}
    {!configured(workflow.pin) ? <Banner tone="warning">Voting is not configured with an independent authority key.</Banner> : !state ? <Restore /> : !state.proof ? <Panel title="Authorization is still pending"><div className="vote-pad"><p>Return to RA with the original account and recover this same request.</p><Backup /><TextLink to="/voter/credentials">Recover credential</TextLink></div></Panel> : state.phase === 'accepted' ? <Panel title="Acceptance receipt" action={<Badge tone="success">Receipt verified</Badge>}><div className="vote-pad"><CheckCircle2 size={36} aria-hidden="true" /><p>The returned receipt matches the digest calculated locally from your exact credential and envelope.</p><label htmlFor="receipt-hash">Receipt hash</label><input id="receipt-hash" className="mono receipt-value" readOnly value={state.receipt_hash ?? ''} /><div className="inline-actions"><Button secondary onClick={()=>void navigator.clipboard.writeText(state.receipt_hash!).then(()=>setCopyMessage('Receipt copied.')).catch(()=>setCopyMessage('Copy unavailable. Select the receipt or download it.'))}>Copy receipt</Button><Button secondary onClick={()=>download('evote-receipt.json',JSON.stringify({version:1,election_id:state.pending.message.election_id,receipt_hash:state.receipt_hash},null,2))}>Download receipt</Button><Backup /></div>{copyMessage && <Banner>{copyMessage}</Banner>}<Banner tone="success">Accepted does not mean counted. Candidate validation, Tally and signed public publication are later steps.</Banner></div></Panel> : <Panel title="Review before submission" action={<Badge tone={state.phase === 'submission_unknown' ? 'amber' : 'success'}>{state.phase === 'submission_unknown' ? 'Outcome uncertain' : 'Credential verified'}</Badge>}><div className="vote-pad"><p className="mono">Election {state.pending.message.election_id}</p><Window bundle={state.bundle} /><p>Your choice is encrypted and was bound before blind signing. A recovered file cannot display the original plaintext choice.</p>{state.phase === 'submission_unknown' && <Banner tone="warning">A previous request may have committed. Check its receipt. Never create another serial or credential.</Banner>}<label className="check-field"><input type="checkbox" checked={confirmed} onChange={event=>setConfirmed(event.target.checked)} />I confirm submission of this exact sealed ballot.</label><div className="inline-actions"><Button disabled={!confirmed || workflow.busy || windowStatus(state.bundle.manifest) !== 'open'} busy={workflow.busy} onClick={()=>void workflow.send(false)}><LockKeyhole size={16} />{state.phase === 'submission_unknown' ? 'Retry identical ballot' : 'Submit ballot'}</Button><Button secondary disabled={workflow.busy} onClick={()=>void workflow.send(true)}><RefreshCw size={16} />Check existing receipt</Button><Backup /></div></div></Panel>}
    <BoundaryNote>Acceptance proves that the Voting service returned a matching committed-record receipt. It is not proof of correct decryption, inclusion in a public Board, or counting. Timing, IP addresses and shared infrastructure can still correlate activity.</BoundaryNote></>;
}

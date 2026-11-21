import { useEffect,useRef,useState } from 'react';
import { useParams } from 'react-router';
import { Banner,Button,EmptyState,Loading,PageHeading,Panel,TextLink,BoundaryNote } from '../components/ui';
import { canonical,fields,uuid } from '../voting/crypto';
import { boardGet,BoardFailure,evidence } from './client';
import { inclusion,Unverified,verifyEvidence,type BoardPins,type Evidence,type Verification } from './verification';

export function PublicWorkspace({pins,mode}:{pins:BoardPins;mode:'list'|'results'|'verify'|'board'}) {
  const {electionId}=useParams();
  const [bundle,setBundle]=useState<Evidence|null>(null),[status,setStatus]=useState<Verification|null>(null);
  const [busy,setBusy]=useState(false),[elections,setElections]=useState<string[]>([]),[cursor,setCursor]=useState<string|null>(null);
  const [feedError,setFeedError]=useState(false);
  const generation=useRef(0);
  async function loadFeed(after:string|null=null) {
    const ticket=++generation.current;setBusy(true);setFeedError(false);
    try {
      const page=await boardGet('/api/v1/board'+(after?'?cursor='+after:''));fields(page,['elections','next_cursor']);
      if(!Array.isArray(page.elections))throw new BoardFailure();
      const ids=page.elections.map(row=>{fields(row,['election_id','status']);uuid(row.election_id);if(row.status!=='PUBLISHED')throw new BoardFailure();return row.election_id;});
      if(page.next_cursor!==null)uuid(page.next_cursor);
      if(ticket===generation.current){setElections(previous=>after?[...new Set([...previous,...ids])]:ids);setCursor(page.next_cursor as string|null);}
    } catch {if(ticket===generation.current)setFeedError(true);} finally{if(ticket===generation.current)setBusy(false);}
  }
  async function check(id:string,hash?:string) {
    const ticket=++generation.current;setBusy(true);setStatus(null);setBundle(null);
    try {
      const verified=await verifyEvidence(await evidence(id),id,pins);
      const outcome=hash?inclusion(verified,hash):'VERIFIED';
      if(ticket===generation.current){setBundle(verified);setStatus(outcome);}
    } catch(error) {
      if(ticket===generation.current)setStatus(error instanceof Unverified?'UNVERIFIED':error instanceof BoardFailure?(error.status===422?'INVALID':'UNAVAILABLE'):'INVALID');
    } finally {if(ticket===generation.current)setBusy(false);}
  }
  useEffect(()=>{setBundle(null);setStatus(null);if(mode==='results' && electionId)void check(electionId);else if(mode!=='verify')void loadFeed();return()=>{generation.current++;};},[mode,electionId,pins]); // No auth state is read; stale navigation results are discarded.
  const report=bundle?.tally.report;
  return <>
    <PageHeading eyebrow="PUBLIC VERIFICATION" title="Published results & evidence" description="Independent checks of signed publication and encrypted ballot inclusion. No voter sign-in." />
    <BoundaryNote>VERIFIED establishes integrity and inclusion under the independently configured keys. It does not prove how an individual choice was decrypted or counted.</BoundaryNote>
    {busy && <Loading>Verifying published evidence…</Loading>}
    {mode!=='results' && mode!=='verify' && <Panel title="Published elections" description="Discovery entries are unverified until their full evidence chain is checked.">
      {feedError?<Banner tone="error">Public election feed unavailable.</Banner>:!elections.length && !busy?<EmptyState title="No published elections">No results have been published.</EmptyState>:<ul style={{overflowWrap:'anywhere'}}>{elections.map(id=><li key={id}><TextLink to={'/public/results/'+id}>Election {id}</TextLink></li>)}</ul>}
      {cursor && <Button disabled={busy} onClick={()=>void loadFeed(cursor)}>Load more elections</Button>}
      <TextLink to="/public/verify">Verify a receipt</TextLink>
    </Panel>}
    {mode==='verify' && <Panel title="Verify published receipt"><form className="admin-form" onSubmit={event=>{
      event.preventDefault();const data=new FormData(event.currentTarget);void check(String(data.get('election')),String(data.get('receipt')));
    }}><label>Election ID<input name="election" required maxLength={36} autoComplete="off" /></label>
      <label>Receipt hash<input name="receipt" required pattern="[0-9a-f]{64}" maxLength={64} autoComplete="off" /></label>
      <Button disabled={busy}>Verify receipt</Button></form><p>No receipt is added to a URL or browser storage. The complete signed snapshot is verified locally before checking inclusion.</p></Panel>}
    {status && <Banner tone={status==='VERIFIED'?'success':status==='INVALID'?'error':'info'}>{status}: {status==='VERIFIED'?'Signed evidence chain verified.':status==='NOT_FOUND'?'Receipt absent from this verified published snapshot.':status==='UNVERIFIED'?'Independent trusted keys are missing.':status==='INVALID'?'Evidence failed verification.':'Published evidence is unavailable or not yet published.'}</Banner>}
    {bundle && (status==='VERIFIED'||status==='NOT_FOUND') && report && <>
      <Panel title="Verified aggregate totals"><dl className="two-columns">{(['accepted_total','valid_total','invalid_total','counted_total'] as const).map(key=><div key={key}><dt>{key.replace('_total','')}</dt><dd>{report[key]}</dd></div>)}</dl></Panel>
      <Panel title="Candidate results" description="Percentages use valid ballots; invalid ballots are reported separately."><ul className="check-list">{bundle.configuration.manifest.candidates.map((c,index)=>{
        const n=report.candidate_counts[index]!.vote_count,percentage=report.valid_total?100*n/report.valid_total:0;
        return <li key={c.candidate_id}><span style={{minWidth:0,overflowWrap:'anywhere'}}>{c.candidate_name}: {n} ({percentage.toFixed(1)}%)</span><meter min={0} max={100} value={percentage} aria-label={c.candidate_name+' percentage'} /></li>;
      })}</ul></Panel>
      <Panel title="Signed evidence metadata"><dl style={{overflowWrap:'anywhere'}}><dt>Configuration SHA-256</dt><dd>{report.election_config_digest}</dd><dt>Snapshot SHA-256</dt><dd>{report.snapshot_digest}</dd><dt>Report SHA-256</dt><dd>{bundle.tally.report_digest}</dd></dl>
        <p>Manifest, snapshot, aggregate report and publication signatures verified. Evidence key: {pins.evidenceKeyId}. Publication key: {pins.publicationKeyId}.</p>
        <Button secondary onClick={()=>{const url=URL.createObjectURL(new Blob([canonical(bundle)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='published-election-'+bundle.election_id+'.json';a.click();URL.revokeObjectURL(url);}}>Download evidence</Button>
        <p>Public evidence contains encrypted envelopes, serials and credential proofs. Preserve this bundle and obtain trust keys independently for offline verification.</p>
      </Panel></>}
    <TextLink to="/public">Published election list</TextLink>
  </>;
}

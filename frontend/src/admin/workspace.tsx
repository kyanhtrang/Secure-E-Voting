import { useEffect, useLayoutEffect, useRef, useState, type FormEvent } from 'react';
import { useLocation } from 'react-router';
import { Badge, Banner, Button, EmptyState, Loading, PageHeading, Panel } from '../components/ui';
import { AdminFailure, createAdminClient, type AdminClient, type AuditEvent, type Election, type Keyset } from './client';
import { PublicationPanel } from './publication';

const failure = (error: unknown) => error instanceof AdminFailure ? error.message : 'Administrative service unavailable.';
function WindowFields({ election }: { election?: Election }) {
  return <><label>Election title<input name="title" required maxLength={255} defaultValue={election?.title} /></label>
    <label>Opens at (UTC)<input name="opens_at" type="datetime-local" step="1" required defaultValue={election?.opens_at.slice(0, 19)} /></label>
    <label>Closes at (UTC)<input name="closes_at" type="datetime-local" step="1" required defaultValue={election?.closes_at.slice(0, 19)} /></label></>;
}
function windowData(form: HTMLFormElement) {
  const data = new FormData(form);
  const utc = (key: string) => { const value = String(data.get(key)); return value.length === 16 ? value + ':00Z' : value + 'Z'; };
  return { title: String(data.get('title')), opens_at: utc('opens_at'), closes_at: utc('closes_at') };
}
export function AdminWorkspace({ client: supplied, publicationEnabled = false }: { client?: AdminClient; publicationEnabled?: boolean }) {
  const client = useRef(supplied ?? createAdminClient(undefined,publicationEnabled)).current;
  const [authenticated, setAuthenticated] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [elections, setElections] = useState<Election[]>([]);
  const [selected, setSelected] = useState<Election | null>(null);
  const [keys, setKeys] = useState<Keyset[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [confirmation, setConfirmation] = useState<'finalize' | 'open' | 'close' | null>(null);
  const [keyset, setKeyset] = useState('');
  const mounted = useRef(true);
  const running = useRef(false), context = useRef(0), refreshSequence = useRef(0);
  const location = useLocation();
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; client.forget(); }; }, [client]);
  // Clear the previous context's confirmation during commit. A passive effect
  // can otherwise erase a fresh confirmation requested after this selection.
  useLayoutEffect(() => { setConfirmation(null); }, [location.pathname, selected?.election_id]);
  useLayoutEffect(() => { context.current++; if (/\/publication$/.test(location.pathname)) { setSelected(null); setEvents([]); } }, [location.pathname]);
  async function run(action: () => Promise<unknown>) {
    if (running.current) return;
    running.current = true;
    const scope = context.current;
    setBusy(true); setError(''); setSuccess('');
    try { await action(); }
    catch (issue) {
      if (mounted.current) {
        if (scope === context.current) setError(failure(issue));
        if (issue instanceof AdminFailure && issue.status === 401) { client.forget(); setAuthenticated(false); setSelected(null); setElections([]); setConfirmation(null); }
      }
    } finally { running.current = false; if (mounted.current) setBusy(false); }
  }
  async function refresh(id = selected?.election_id) {
    const scope = context.current, sequence = ++refreshSequence.current;
    const current = () => mounted.current && scope === context.current && sequence === refreshSequence.current;
    const [list, catalogue] = await Promise.all([client.list(), client.keys()]);
    if (!current()) return;
    setElections(list.elections); setKeys(catalogue.keysets);
    if (id) { const [election, audit] = await Promise.all([client.detail(id), client.audit(id)]); if (!current()) return;
      if (election.election_id !== id) throw new AdminFailure(); setSelected(election); setEvents(audit.events); return election; }
  }
  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
    const username = String(data.get('username')); const password = String(data.get('password')); form.reset();
    const scope = context.current;
    await run(async () => { await client.login(username, password); await refresh(); if (mounted.current && scope === context.current) setAuthenticated(true); });
  }
  if (!authenticated) return <><PageHeading eyebrow="LOCAL ADMINISTRATION" title="Administrator sign-in" description="Separate authorization is required. A voter session cannot administer elections." />
    {error && <Banner tone="error">{error}</Banner>}<Panel title="Local administrator"><form className="admin-form" onSubmit={login}>
      <label>Admin username<input name="username" autoComplete="username" required maxLength={255} /></label>
      <label>Admin password<input name="password" type="password" autoComplete="current-password" required maxLength={1024} /></label>
      <Button disabled={busy} busy={busy}>Sign in as administrator</Button></form></Panel></>;
  const pendingOnly = /\/tally$/.test(location.pathname);
  const publicationPage = /\/publication$/.test(location.pathname);
  async function change(action: string, method: string, data: unknown) {
    if (!selected) return;
    const scope = context.current;
    const next = await client.change(selected.election_id, action, method, data);
    if (!mounted.current || scope !== context.current) return;
    setSelected(next); await refresh(next.election_id); if (mounted.current && scope === context.current) setSuccess('Operation committed. Configuration and audit refreshed.');
  }
  return <>
    <PageHeading eyebrow="AUTHORIZED LOCAL ADMINISTRATION" title="Election management" description="Draft, verify, sign and reconcile election configuration across RA and Voting.">
      <Button secondary disabled={busy} onClick={() => void run(async () => { try { await client.logout(); } finally { setAuthenticated(false); setSelected(null); setElections([]); } })}>Admin logout</Button>
    </PageHeading>
    {error && <Banner tone="error">{error}</Banner>}{success && <Banner tone="success">{success}</Banner>}
    {!publicationPage && <Banner>Opening and closing use separate database commits. A partial failure requires refresh and retry of the same operation. Signed parameters cannot be edited.</Banner>}
    {pendingOnly ? <Panel title="Future service"><EmptyState title="Tally and publication are unavailable">No decryption, counting or publication operations are enabled.</EmptyState><Button disabled>Start operation</Button></Panel> : <>
    <Panel title="Managed elections" action={<Button secondary disabled={busy} onClick={() => void run(() => refresh())}>Refresh status</Button>}>
      {busy && <Loading>Contacting the admin service…</Loading>}
      {!elections.length ? <EmptyState title="No managed elections">Create a draft to begin. Existing unmanaged elections remain outside this workspace.</EmptyState> : <div className="admin-grid">{elections.map(election => <Button secondary key={election.election_id} disabled={busy} onClick={() => void run(() => refresh(election.election_id))}>{election.title} · {election.status}</Button>)}</div>}
    </Panel>
    {!publicationPage && <Panel title="Create draft election"><form className="admin-form" onSubmit={event => { event.preventDefault(); const form = event.currentTarget; const data = windowData(form); void run(async () => { const election = await client.create(data); form.reset(); await refresh(election.election_id); }); }}>
      <WindowFields /><Button disabled={busy}>Create draft</Button></form></Panel>}
    {selected && <div key={selected.election_id}>
      <Panel title={selected.title} action={<Badge tone={selected.ra_ready ? 'success' : 'amber'}>{selected.phase} · {selected.ra_ready ? 'RA reconciled' : 'Reconciliation pending'}</Badge>}>
        <p>Election ID: <code>{selected.election_id}</code></p><p>Voting window: {selected.opens_at} — {selected.closes_at}</p>
        <p>Configuration hash: <code>{selected.config_hash ?? 'Not signed'}</code></p>
        {!publicationPage && selected.phase === 'DRAFT' && <form key={selected.revision} className="admin-form" onSubmit={event => { event.preventDefault(); const data = windowData(event.currentTarget); void run(() => change('', 'PUT', { ...data, revision: selected.revision })); }}><WindowFields election={selected} /><Button disabled={busy}>Save voting window</Button></form>}
      </Panel>
      {!publicationPage && <>
      <Panel title="Candidate roster"><ul>{selected.candidates.map(candidate => <li key={candidate.candidate_id}>
        {selected.phase === 'DRAFT' ? <form className="admin-candidate" onSubmit={event => { event.preventDefault(); const name = String(new FormData(event.currentTarget).get('candidate_name')); void run(() => change('/candidates/' + candidate.candidate_id, 'PUT', { revision: selected.revision, candidate_name: name })); }}>
          <label>Candidate name<input name="candidate_name" required maxLength={128} defaultValue={candidate.candidate_name} /></label>
          <Button secondary disabled={busy}>Update</Button><Button secondary type="button" disabled={busy} onClick={() => void run(() => change('/candidates/' + candidate.candidate_id, 'DELETE', { revision: selected.revision }))}>Remove</Button>
        </form> : candidate.candidate_name}</li>)}</ul>
        {!selected.candidates.length && <p>No candidates configured.</p>}
        {selected.phase === 'DRAFT' && <form className="admin-form" onSubmit={event => { event.preventDefault(); const form = event.currentTarget; const name = String(new FormData(form).get('candidate_name')); void run(async () => { await change('/candidates', 'POST', { revision: selected.revision, candidate_name: name }); form.reset(); }); }}><label>New candidate<input name="candidate_name" required maxLength={128} /></label><Button disabled={busy}>Add candidate</Button></form>}
      </Panel>
      <Panel title="Configuration review and lifecycle">
        <label>Approved signing keyset<select value={selected.keyset_id || keyset || ''} disabled={selected.phase !== 'DRAFT' || busy} onChange={event => setKeyset(event.target.value)}><option value="">Select a provisioned keyset</option>{keys.map(key => <option key={key.keyset_id}>{key.keyset_id}</option>)}</select></label>
        {keys.filter(key => key.keyset_id === (selected.keyset_id || keyset)).map(key => <div key={key.keyset_id}><p>RA public fingerprint: <code>{key.ra_key.fingerprint}</code></p><p>Tally public fingerprint: <code>{key.tally_key.fingerprint}</code></p></div>)}
        <div className="inline-actions"><Button disabled={busy || !['DRAFT','FINALIZING','FROZEN'].includes(selected.phase) || !(selected.keyset_id || keyset)} onClick={() => setConfirmation('finalize')}>Finalize signed configuration</Button>
          <Button disabled={busy || !['FROZEN','OPEN'].includes(selected.phase)} onClick={() => setConfirmation('open')}>Open / reconcile opening</Button>
          <Button secondary disabled={busy || !['OPEN','CLOSED'].includes(selected.phase)} onClick={() => setConfirmation('close')}>Close / reconcile closure</Button></div>
        {confirmation && <section role="region" aria-label="Confirm election operation"><Banner tone="warning">Confirm {confirmation} for {selected.title}. Signing permanently freezes the roster, window and keys; closure cannot be reversed.</Banner>
          <Button disabled={busy} onClick={() => void run(async () => { await change('/' + confirmation, 'POST', confirmation === 'finalize' ? { revision: selected.revision, keyset_id: selected.keyset_id || keyset } : {}); setConfirmation(null); })}>Confirm {confirmation}</Button>
          <Button secondary disabled={busy} onClick={() => setConfirmation(null)}>Cancel</Button></section>}
      </Panel>
      </>}
      {publicationPage && <PublicationPanel key={selected.election_id} client={client} election={selected} enabled={publicationEnabled} busy={busy} run={run} refresh={refresh} />}
      <Panel title="Administration audit"><ul>{events.map((event, index) => <li key={index}>{event.occurred_at} · {event.event_type} · {event.outcome} {event.reason_code ?? ''}</li>)}</ul>{!events.length && <p>No operational events available.</p>}</Panel>
    </div>}
    </>}
  </>;
}

import { useEffect, useRef, useState } from 'react';
import { Banner, Button, EmptyState, Loading, PageHeading, Panel } from '../components/ui';
import { createTallyClient, TallyFailure, type TallyClient, type TallyElection, type TallyReport } from './client';

export function TallyWorkspace({ client: supplied }: { client?: TallyClient }) {
  const client = useRef(supplied ?? createTallyClient()).current;
  const [authorized, setAuthorized] = useState(false), [busy, setBusy] = useState(false);
  const [error, setError] = useState(''), [elections, setElections] = useState<TallyElection[]>([]);
  const [selected, setSelected] = useState(''), [confirmed, setConfirmed] = useState(false), [report, setReport] = useState<TallyReport | null>(null);
  const active = useRef(true);
  useEffect(() => { active.current = true; return () => { active.current = false; client.forget(); }; }, [client]);
  async function run(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError('');
    try { await action(); }
    catch (failure) {
      if (active.current) {
        setError(failure instanceof TallyFailure ? failure.message : 'Restricted Tally service unavailable.');
        if (failure instanceof TallyFailure && failure.status === 401) { client.forget(); setAuthorized(false); setReport(null); setElections([]); setSelected(''); setConfirmed(false); }
      }
    } finally { if (active.current) setBusy(false); }
  }
  async function refresh() { const data = await client.elections(); if (active.current) setElections(data.elections); }
  const election = elections.find(value => value.election_id === selected);
  return <><PageHeading eyebrow="RESTRICTED TALLY" title="Verify and count closed elections" description="Separate Tally operator authorization is required. Only aggregate results are shown; publication remains disabled." />
    {error && <Banner tone="error">{error}</Banner>}
    {!authorized ? <Panel title="Tally operator sign-in"><form className="admin-form" onSubmit={event => {
      event.preventDefault(); const form = event.currentTarget, data = new FormData(form);
      const username = String(data.get('username')), password = String(data.get('password')); form.reset();
      void run(async () => { await client.login(username, password); await refresh(); setAuthorized(true); });
    }}><label>Tally username<input name="username" autoComplete="username" maxLength={255} required /></label>
      <label>Tally password<input name="password" type="password" autoComplete="current-password" maxLength={1024} required /></label><Button disabled={busy}>Sign in to Tally</Button></form>
      <Banner>Election Admin and voter credentials do not authorize Tally. Keys are unlocked only in the separate backend process.</Banner></Panel> : <>
      <div className="inline-actions"><Button secondary disabled={busy} onClick={() => void run(refresh)}>Refresh elections</Button>
        <Button secondary disabled={busy} onClick={() => void run(async () => { try { await client.logout(); } finally { setAuthorized(false); setReport(null); setElections([]); setSelected(''); setConfirmed(false); } })}>Tally logout</Button></div>
      {busy && <Loading>Verifying the private snapshot and tally transaction…</Loading>}
      <Panel title="Closed elections">
        {!elections.length ? <EmptyState title="No closed elections available">A reconciled CLOSED election is required before counting.</EmptyState> : <label>Election<select value={selected} disabled={busy} onChange={event => { setSelected(event.target.value); setConfirmed(false); setReport(null); }}><option value="">Select an election</option>{elections.map(value => <option key={value.election_id} value={value.election_id}>{value.title} · {value.status}</option>)}</select></label>}
        {election && <><p>Status: {election.status} · {election.ra_ready ? 'RA reconciliation complete' : 'Reconciliation pending'}</p>
          <label><input type="checkbox" checked={confirmed} disabled={busy || election.status !== 'CLOSED' || !election.ra_ready} onChange={event => setConfirmed(event.target.checked)} /> I authorize restricted verification and tallying for this election.</label>
          <div className="inline-actions"><Button disabled={busy || !confirmed || election.status !== 'CLOSED' || !election.ra_ready} onClick={() => void run(async () => { setReport(await client.run(selected)); setConfirmed(false); await refresh(); })}>Verify and tally</Button>
            <Button secondary disabled={busy} onClick={() => void run(async () => { setReport(await client.report(selected)); await refresh(); })}>Recover committed report</Button></div></>}
      </Panel>
      <Banner>After a lost response, recover the committed report before retrying. Invalid encrypted or plaintext ballots are included in explicit invalid totals. Acceptance receipts retain their original meaning.</Banner>
      {report && <Panel title="Restricted aggregate report"><div className="metrics">{(['accepted_total', 'valid_total', 'invalid_total', 'counted_total'] as const).map(field => <div className="metric" key={field}><span>{field.replace('_total', '')}</span><strong>{report.report[field]}</strong></div>)}</div>
        <table><thead><tr><th>Candidate</th><th>Count</th></tr></thead><tbody>{report.report.candidate_counts.map(row => <tr key={row.candidate_id}><td>{report.candidates.find(value => value.candidate_id === row.candidate_id)?.candidate_name ?? row.candidate_id}</td><td>{row.vote_count}</td></tr>)}</tbody></table>
        <p>Invalid reasons: key wrap {report.report.invalid_reasons.KEY_WRAP}, authentication {report.report.invalid_reasons.AEAD}, plaintext {report.report.invalid_reasons.PLAINTEXT}.</p>
        <p>Snapshot digest: <code>{report.report.snapshot_digest}</code></p><p>Report digest: <code>{report.report_digest}</code></p><p>Snapshot signing key: {report.signing_key_id}</p>
        <Banner>Verified by the authorized Tally service and its private evidence. This is not a public publication or proof of complete end-to-end tally correctness.</Banner>
      </Panel>}
    </>}</>;
}

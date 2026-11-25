import { useLayoutEffect, useRef, useState } from 'react';
import { Banner, Button, Panel, TextLink } from '../components/ui';
import { AdminFailure, PublicationFailure, type AdminClient, type Election, type PublicationResult } from './client';

export function PublicationPanel({ client, election, enabled, busy, run, refresh }: {
  client: AdminClient; election: Election; enabled: boolean; busy: boolean;
  run: (action: () => Promise<void>) => Promise<void>; refresh: (id: string) => Promise<Election | undefined>;
}) {
  const [confirmed, setConfirmed] = useState(false), [outcome, setOutcome] = useState<'ready'|'unknown'|'reviewed'>('ready');
  const [acknowledgement, setAcknowledgement] = useState<PublicationResult | null>(null);
  const active = useRef(true);
  useLayoutEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  const published = election.phase === 'PUBLISHED' && election.status === 'PUBLISHED';
  const ready = enabled && election.phase === 'TALLIED' && election.status === 'TALLIED' && election.ra_ready
    && /^[0-9a-f]{64}$/.test(election.config_hash ?? '') && outcome !== 'unknown';
  async function publish() {
    if (!ready || !confirmed || busy) return;
    await run(async () => {
      setConfirmed(false); setOutcome('unknown');
      let response: PublicationResult | undefined, issue: unknown;
      try { response = await client.publish(election.election_id); }
      catch (error) { if (error instanceof AdminFailure && error.status === 401) throw error; issue = error; }
      if (!active.current) return;
      // A lost response may follow a committed transaction. Never POST again here.
      let current: Election | undefined;
      try { current = await refresh(election.election_id); }
      catch (error) { if (error instanceof AdminFailure && error.status === 401) throw error; throw new PublicationFailure(503,true); }
      if (!active.current) return;
      if (current?.election_id === election.election_id && current.phase === 'PUBLISHED' && current.status === 'PUBLISHED') {
        setOutcome('ready'); setAcknowledgement(response ?? null); return;
      }
      if (issue instanceof PublicationFailure && !issue.uncertain) setOutcome('ready');
      if (issue) throw issue;
      throw new PublicationFailure(503,true);
    });
  }
  return <Panel title="Publish election results">
    <p>Lifecycle: <strong>{election.status}</strong> · {election.ra_ready ? 'RA reconciliation complete' : 'Reconciliation pending'}</p>
    <p>Evidence status: {published ? 'Committed publication recorded. Independent public verification is available.'
      : election.phase === 'TALLIED' ? 'Committed Tally indicated by lifecycle. Publisher must verify the signed report, snapshot and configuration before publication.'
      : 'A successful committed Tally is required before publication.'}</p>
    {!enabled && <Banner>Publication is disabled. Explicit local Admin and Publisher configuration is required.</Banner>}
    <Banner>Only an explicitly enrolled Publisher may publish. Signing keys and passphrases stay in the separate Publisher service.</Banner>
    {published ? <><Banner tone="success">PUBLISHED — publication is committed.</Banner>
      <TextLink to={'/public/results/' + election.election_id}>Open public results and independent verification</TextLink>
      {acknowledgement && <p>Publisher acknowledgement digest: <code>{acknowledgement.bundle_digest}</code></p>}</>
      : <><Button disabled={busy || !ready} onClick={() => setConfirmed(true)}>Publish results</Button>
        {confirmed && ready && <section role="region" aria-label="Confirm publication">
          <Banner tone="warning">Publish results for {election.title}? This makes signed encrypted evidence and aggregate totals public and permanently sets PUBLISHED.</Banner>
          <Button disabled={busy} onClick={() => void publish()}>Confirm publish</Button>
          <Button secondary disabled={busy} onClick={() => setConfirmed(false)}>Cancel publication</Button></section>}</>}
    <div className="inline-actions"><Button secondary disabled={busy} onClick={() => {
      setConfirmed(false);
      void run(async () => { const current = await refresh(election.election_id);
        if (active.current && current?.election_id === election.election_id) setOutcome(current.phase === 'PUBLISHED' ? 'ready' : outcome === 'unknown' ? 'reviewed' : outcome); });
    }}>Refresh publication status</Button></div>
    {outcome === 'unknown' && !published && <Banner tone="warning">Publication outcome is unknown. Refresh authoritative state before another attempt. No automatic publication retry is performed.</Banner>}
    {outcome === 'reviewed' && !published && <Banner tone="warning">The latest state has been refreshed. A previous request may still complete. An explicit retry repeats the same idempotent election publication.</Banner>}
    <p>Publication and receipt inclusion do not prove individual decryption correctness or complete end-to-end tally correctness. Public verification uses independently configured trust pins and needs no Admin session.</p>
  </Panel>;
}

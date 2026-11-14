import { BarChart3, CalendarDays, FileCheck2, Fingerprint, Globe2, ListChecks, LockKeyhole, ShieldCheck } from 'lucide-react';
import { Badge, Banner, BoundaryNote, Button, EmptyState, PageHeading, Panel, PublicationGate, TextLink, UnavailableTotals } from '../components/ui';

export function PublicOverview() {
  return <>
    <PageHeading eyebrow="PUBLIC TRANSPARENCY" title="Election outcomes, open to everyone." description="Inspect published results and the evidence behind them. No voter account is required."><Badge>Public access</Badge></PageHeading>
    <div className="public-hero"><div><span className="eyebrow">EVIDENCE BEFORE CONFIDENCE</span><h2>Results deserve<br /><em>more than a promise.</em></h2><p>This workspace is designed for published outcomes, signed evidence, and independent receipt verification.</p>
      <TextLink to="/public/verify">Receipt verification workspace</TextLink></div><Globe2 size={140} strokeWidth={0.65} aria-hidden="true" /></div>
    <Panel title="Published elections" description="Results become visible only after publication." action={<Badge tone="amber">Publication feed unavailable</Badge>}>
      <EmptyState icon={CalendarDays} title="No publication feed is connected">The backend does not expose a published-election list. No election names, outcomes, vote totals, or publication evidence are shown.</EmptyState>
    </Panel>
    <div className="two-columns"><Panel title="Public bulletin board" description="A place for inspectable election evidence."><EmptyState icon={ListChecks} title="Evidence feed pending">Accepted ballot records and signed evidence require a defined public backend contract.</EmptyState><div className="panel-actions"><TextLink to="/public/board">Open bulletin board workspace</TextLink></div></Panel>
      <Panel title="Publication safeguards" description="A shared standard for presenting results."><ul className="check-list"><li><ShieldCheck size={18} />Results gated on PUBLISHED</li><li><LockKeyhole size={18} />No RA session required or sent</li><li><FileCheck2 size={18} />No invented counts or evidence</li></ul></Panel></div>
  </>;
}
export function PublicResults() {
  // Intentionally unavailable: there is no publication endpoint or response DTO.
  // Route/query parameters cannot authorize results or manufacture publication.
  const publicationStatus: unknown = undefined;
  const unavailable = <>
    <Banner>Results are unavailable. A verified publication source must establish PUBLISHED status before any results are displayed.</Banner>
    <UnavailableTotals />
    <div className="two-columns"><Panel title="Candidate results" description="Published candidate totals will appear here.">
      <div className="chart-placeholder"><div className="chart-grid" aria-hidden="true" /><div><BarChart3 size={30} aria-hidden="true" /><strong>No published chart data</strong><p>No candidates or vote values are supplied.</p></div></div>
    </Panel><Panel title="Signed publication & audit evidence"><EmptyState icon={FileCheck2} title="No publication evidence">No signed result manifest, publication signature, or audit evidence is available from a backend API.</EmptyState></Panel></div>
  </>;
  return <><TextLink to="/public">Back to published elections</TextLink>
    <PageHeading eyebrow="PUBLIC RESULTS" title="Election results" description="Publication is a prerequisite for showing an election’s outcome."><Badge>Publication unavailable</Badge></PageHeading>
    <PublicationGate status={publicationStatus} fallback={unavailable}>
      {/* No published data renderer is wired until its real contract is reviewed. */}
      <EmptyState title="Publication contract required">No results contract is connected.</EmptyState>
    </PublicationGate>
    <BoundaryNote>Neither a link, a query parameter, nor an authenticated voter session can establish PUBLISHED status.</BoundaryNote>
  </>;
}
export function BulletinBoard() {
  return <><PageHeading eyebrow="PUBLIC EVIDENCE" title="The public bulletin board" description="An inspectable record of published election evidence." />
    <Panel title="Published records" action={<Badge>API unavailable</Badge>}><EmptyState icon={ListChecks} title="No bulletin board feed is connected">
      Accepted ballot records, signed publications, and audit evidence will need a defined public contract. No record is fabricated here.
    </EmptyState></Panel><div className="panel-actions"><TextLink to="/public/verify">Go to receipt verification</TextLink></div>
  </>;
}
export function VerifyReceipt() {
  return <><PageHeading eyebrow="PUBLIC VERIFICATION" title="Every receipt needs real evidence." description="A dedicated space for independent receipt checks, without a voter login." />
    <div className="two-columns"><Panel title="Verify a receipt" description="Verification is not connected in this foundation."><div className="receipt-form">
      <div className="field"><label htmlFor="receipt">Receipt reference</label><input id="receipt" disabled placeholder="Available when the verification service is connected" aria-describedby="receipt-help" /></div>
      <p id="receipt-help" className="fine-print">The receipt format and verification API have not been defined. Submission is disabled; no reference is sent or stored.</p>
      <Button disabled><Fingerprint size={17} />Verify receipt</Button></div></Panel>
      <Panel title="What a future check must establish"><ul className="check-list"><li><FileCheck2 size={18} />A matching published election</li><li><ListChecks size={18} />Evidence from its bulletin board</li><li><ShieldCheck size={18} />Reviewed signature verification</li></ul><BoundaryNote>A visual success message is not proof. Verification requires authentic published evidence.</BoundaryNote></Panel></div>
  </>;
}
export function AnonymousVoting() {
  return <><PageHeading eyebrow="ANONYMOUS WORKSPACE" title="Anonymous voting is not connected" description="This is a separate future boundary. No RA identity or session token is used here." />
    <Panel title="Voting availability"><EmptyState icon={LockKeyhole} title="Submission is unavailable">Anonymous credential verification, ballot submission and receipt contracts are not implemented. No vote can be submitted from this screen.</EmptyState><div className="panel-actions"><Button disabled>Submit ballot</Button></div></Panel>
  </>;
}

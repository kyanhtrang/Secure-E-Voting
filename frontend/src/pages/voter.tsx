import { type FormEvent } from 'react';
import { Navigate, Outlet } from 'react-router';
import { ArrowRight, CalendarDays, Check, CheckCircle2, Circle, Fingerprint, KeyRound, LockKeyhole, LogOut, RefreshCw, ShieldCheck } from 'lucide-react';
import { useSession } from '../auth/session';
import { Badge, Banner, BoundaryNote, Button, EmptyState, Loading, PageHeading, Panel, TextLink } from '../components/ui';

export function RequireSession() {
  const session = useSession();
  if (session.phase === 'anonymous' || session.phase === 'signing-in') return <Navigate to="/voter/login" replace />;
  if (session.phase === 'checking') return <Loading />;
  if (session.phase === 'unavailable') return <>
    <PageHeading eyebrow="VOTER ACCESS" title="We couldn’t check your session" description="Your access must be verified before continuing." />
    <Banner tone="error">{session.message}</Banner><div className="inline-actions">
      <Button onClick={() => void session.refresh()}>Try again</Button><Button secondary onClick={() => void session.logout()}>Sign out on this device</Button></div>
  </>;
  return <Outlet />;
}

function BallotArt() {
  return <div className="ballot-art" aria-hidden="true"><div className="orbit orbit-one" /><div className="orbit orbit-two" />
    <div className="floating-lock"><LockKeyhole size={19} /></div><div className="ballot-paper"><div className="paper-label">YOUR VOICE</div>
      <div className="paper-option"><span /><i /></div><div className="paper-option chosen"><span><Check size={16} /></span><i /></div>
      <div className="paper-option"><span /><i /></div></div><div className="ballot-box"><div className="ballot-slot" /><ShieldCheck size={43} strokeWidth={1.3} /></div>
    <span className="art-spark spark-one" /><span className="art-spark spark-two" /></div>;
}
export function Login() {
  const session = useSession();
  if (session.phase === 'authenticated') return <Navigate to="/voter" replace />;
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const username = String(data.get('username') ?? '');
    const password = String(data.get('password') ?? '');
    (form.elements.namedItem('password') as HTMLInputElement).value = '';
    void session.login(username, password);
  };
  return <>
    <PageHeading eyebrow="VOTER WORKSPACE" title="A trusted place for your voice." description="Sign in to begin your secure voting journey." />
    <div className="login-grid">
      <section className="login-story" aria-label="About secure participation"><div className="story-tag"><span /> PRIVATE BY DESIGN</div>
        <h2>Your voice matters.<br /> <em>Your privacy<br /> shapes the design.</em></h2>
        <p>A considered approach to private participation, built on reviewed cryptographic foundations.</p>
        <BallotArt />
        <div className="story-bottom"><ShieldCheck size={17} aria-hidden="true" /><span>Identity and anonymous voting are separate.</span></div>
      </section>
      <section className="login-form-panel"><div className="form-heading-icon"><Fingerprint size={25} aria-hidden="true" /></div>
        <h2>Welcome to your workspace</h2><p className="form-intro">Use your local demo voter credentials to sign in.</p>
        {session.message && <Banner tone={session.message === 'You have signed out.' ? 'success' : 'warning'}>{session.message}</Banner>}
        {!session.enabled && <Banner>Local sign-in is not connected. Start this frontend in its explicitly enabled local-demo mode to connect to the RA launcher.</Banner>}
        <form onSubmit={submit} aria-label="Voter sign-in">
          <div className="field"><label htmlFor="username">Username</label><input id="username" name="username" autoComplete="username" maxLength={256}
            required disabled={!session.enabled || session.busy} placeholder="Your demo username" /></div>
          <div className="field"><label htmlFor="password">Password</label><input id="password" name="password" type="password" autoComplete="current-password"
            required maxLength={1024} disabled={!session.enabled || session.busy} placeholder="Enter your password" /></div>
          <div className="form-security"><LockKeyhole size={14} aria-hidden="true" /><span>Session access stays in this browser’s memory.</span></div>
          <Button type="submit" className="full-width" disabled={!session.enabled || session.busy} busy={session.busy}>
            {session.busy ? 'Verifying your access…' : 'Sign in securely'}{!session.busy && <ArrowRight size={17} aria-hidden="true" />}</Button>
        </form>
        <div className="login-note"><strong>A local research demonstration</strong><p>Use only the account configured for this local demo. Refreshing or leaving the voter workspace clears access on this device.</p></div>
        <div className="public-invitation">Looking for election outcomes?<TextLink to="/public">Explore public results</TextLink></div>
      </section>
    </div>
    <div className="principle-strip"><div><ShieldCheck size={19} /><span><strong>Verified access</strong><small>Sessions checked by the RA</small></span></div>
      <div><KeyRound size={19} /><span><strong>Blind credential foundation</strong><small>Reviewed RFC 9474 protocol</small></span></div>
      <div><Fingerprint size={19} /><span><strong>Public accountability</strong><small>Publication and verification planned</small></span></div></div>
  </>;
}

export function VoterOverview({votingEnabled=false}: {votingEnabled?:boolean}) {
  const session = useSession();
  return <>
    <PageHeading eyebrow="YOUR VOTER WORKSPACE" title="Ready when your election is." description={votingEnabled ? 'Choose a signed election, protect your request, then continue to separate anonymous voting.' : 'Your session is verified. Election access will appear here when the catalogue is connected.'}>
      <Badge tone="success">Session verified</Badge>
    </PageHeading>
    <div className="overview-hero"><div><span className="eyebrow">PARTICIPATE WITH CONFIDENCE</span><h2>One election. One credential.<br /><em>Your choice stays yours.</em></h2>
      <p>Your RA session confirms who you are. Election eligibility is a separate check, and anonymous voting {votingEnabled ? 'uses' : 'will use'} a separate credential.</p>
      <TextLink to="/voter/elections">Explore election access</TextLink></div><div className="hero-seal" aria-hidden="true"><ShieldCheck size={65} strokeWidth={1.1} /><span>SECURE BY DESIGN</span></div></div>
    <div className="two-columns">
      <Panel title="Your participation journey" description="What works today, and what comes next.">
        <ol className="journey"><li className="complete"><span className="journey-icon"><CheckCircle2 size={19} /></span><div><strong>Verify your voter session</strong><p>Authenticated through the local Registration Authority.</p></div><Badge tone="success">Complete</Badge></li>
          <li><span className="journey-icon"><CalendarDays size={19} /></span><div><strong>{votingEnabled ? 'Choose a verified election' : 'Choose an eligible election'}</strong><p>{votingEnabled ? 'Signed candidate catalogue; eligibility is checked by RA on issuance.' : 'Requires an election catalogue and eligibility contract.'}</p></div><Badge>{votingEnabled ? 'Available' : 'Pending'}</Badge></li>
          <li><span className="journey-icon"><KeyRound size={19} /></span><div><strong>Prepare a voting credential</strong><p>{votingEnabled ? 'Encrypt locally, blind, and save protected recovery before issuance.' : 'Client blinding and protected recovery need browser integration.'}</p></div><Badge>{votingEnabled ? 'Available' : 'Planned'}</Badge></li>
          <li><span className="journey-icon"><Circle size={19} /></span><div><strong>Vote in the anonymous workspace</strong><p>{votingEnabled ? 'Submit without RA authentication and verify the acceptance receipt.' : 'Anonymous submission and verification are not available yet.'}</p></div><Badge>{votingEnabled ? 'Available' : 'Planned'}</Badge></li></ol>
      </Panel>
      <Panel title="Session & access" description="The RA is the authority on session validity.">
        <div className="session-body"><div className="session-verified"><span><ShieldCheck size={24} /></span><div><strong>Verified local session</strong><small>RA identity confirmed</small></div></div>
          <dl className="session-facts"><div><dt>Voter reference</dt><dd>{session.identity?.voter_id.slice(0, 8)}…</dd></div><div><dt>Storage</dt><dd>Memory only</dd></div>
            <div><dt>Last checked</dt><dd>{session.checkedAt?.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) ?? '—'}</dd></div></dl>
          <p className="fine-print">Checked again while this workspace is open. No expiry time is supplied by the current API.</p>
          <div className="inline-actions"><Button secondary disabled={session.busy} onClick={() => void session.refresh()}><RefreshCw size={15} />Check session</Button>
            <Button secondary disabled={session.busy} onClick={() => void session.logout()}><LogOut size={15} />Sign out</Button></div></div>
      </Panel>
    </div>
    <BoundaryNote>Signing in verifies your RA session. It does not confirm eligibility for any election, cast a vote, or grant administrator access.</BoundaryNote>
  </>;
}

export function Elections() {
  return <>
    <PageHeading eyebrow="VOTER ELECTIONS" title="Find your election" description="A clear view of the elections you can participate in." />
    <Panel title="Election catalogue" description="Election metadata and voter eligibility are not connected." action={<Badge tone="amber">API unavailable</Badge>}>
      <div className="table-scroll"><table><thead><tr><th>Election</th><th>Voting period</th><th>Status</th><th>Access</th></tr></thead><tbody><tr><td colSpan={4}>
        <EmptyState icon={CalendarDays} title="No election catalogue is connected">The current backend has no election-listing API. No election records, eligibility decisions, or voting dates are displayed.</EmptyState>
      </td></tr></tbody></table></div>
    </Panel><BoundaryNote>We’ll only display elections supplied by a defined backend contract. No sample election is presented as a live election.</BoundaryNote>
  </>;
}
export function ElectionDetail() {
  return <><TextLink to="/voter/elections">Back to elections</TextLink>
    <PageHeading eyebrow="ELECTION DETAILS" title="Election details are unavailable" description="This workspace cannot resolve an election without an election-detail contract." />
    <Panel title="Election information"><EmptyState icon={CalendarDays} title="No verified election metadata">An election identifier in a link is not evidence that the election exists or that a voter is eligible.</EmptyState></Panel>
    <div className="inline-actions"><Button disabled>Request credential</Button><Button secondary disabled>Continue to voting</Button></div>
  </>;
}
export function Credentials() {
  return <>
    <PageHeading eyebrow="VOTING CREDENTIAL" title="Your private credential journey" description="Blind signing is implemented in the RA. Browser issuance is not connected in this foundation." />
    <Panel title="Credential preparation" action={<Badge>Browser integration pending</Badge>}>
      <EmptyState icon={KeyRound} title="No credential has been requested">Trusted election configuration, client-side blinding, and durable protected recovery must be connected before enabling issuance.</EmptyState>
      <div className="panel-actions"><Button disabled>Prepare voting credential</Button></div>
      <div className="panel-actions"><TextLink to="/vote">Preview the separate anonymous workspace</TextLink></div>
    </Panel><BoundaryNote>This screen does not call the issuance API or consume an election authorization. No serial, ballot choice, or finalized credential is sent to the RA.</BoundaryNote>
  </>;
}

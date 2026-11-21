import { Component, type ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import type { AuthClient } from './api/auth';
import { SessionProvider } from './auth/session';
import { Shell } from './components/shell';
import { PageHeading, TextLink } from './components/ui';
import { config, type AppConfig } from './config';
import { TallyWorkspace } from './tally/workspace';
import { AdminWorkspace } from './admin/workspace';
import { AdminOverview, AdminSection } from './pages/admin';
import { AnonymousVoting, BulletinBoard, PublicOverview, PublicResults, VerifyReceipt } from './pages/public';
import { Credentials, ElectionDetail, Elections, Login, RequireSession, VoterOverview } from './pages/voter';
import { VotingBallot, VotingCredentials, VotingElectionDetail, VotingElections } from './pages/voting';
import { VotingProvider } from './voting/context';
import { PublicWorkspace } from './board/workspace';

export function App({ settings = config, client }: { settings?: AppConfig; client?: AuthClient }) {
  const publicPage=(mode:'list'|'results'|'verify'|'board',fallback:ReactNode)=>settings.boardEnabled && settings.boardPins
    ? <PublicWorkspace mode={mode} pins={settings.boardPins} />:fallback;
  const routes=<Routes>
    <Route path="/" element={<Navigate to="/voter" replace />} />
    <Route path="/voter" element={<SessionProvider enabled={settings.authEnabled} {...(client ? { client } : {})}><Shell workspace="voter" /></SessionProvider>}>
      <Route path="login" element={<Login />} />
      <Route element={<RequireSession />}>
        <Route index element={<VoterOverview votingEnabled={settings.votingEnabled ?? false} />} />
        <Route path="elections" element={settings.votingEnabled ? <VotingElections /> : <Elections />} />
        <Route path="elections/:electionId" element={settings.votingEnabled ? <VotingElectionDetail /> : <ElectionDetail />} />
        <Route path="credentials" element={settings.votingEnabled ? <VotingCredentials /> : <Credentials />} />
      </Route>
    </Route>
    <Route path="/admin" element={<Shell workspace="admin" adminEnabled={settings.adminEnabled || settings.tallyEnabled || false} />}>
      {settings.tallyEnabled && <Route path="tally" element={<TallyWorkspace />} />}
      <Route index element={settings.adminEnabled ? <AdminWorkspace /> : <AdminOverview />} /><Route path=":section" element={settings.adminEnabled ? <AdminWorkspace /> : <AdminSection />} />
    </Route>
    <Route path="/public" element={<Shell workspace="public" />}>
      <Route index element={publicPage('list',<PublicOverview />)} /><Route path="results/:electionId" element={publicPage('results',<PublicResults />)} />
      <Route path="board" element={publicPage('board',<BulletinBoard />)} /><Route path="verify" element={publicPage('verify',<VerifyReceipt />)} />
    </Route>
    <Route element={<Shell workspace="public" />}><Route path="/vote" element={settings.votingEnabled ? <VotingBallot /> : <AnonymousVoting />} />
      <Route path="*" element={<><PageHeading eyebrow="PAGE NOT FOUND" title="This page isn’t available" description="Choose a workspace to continue." /><TextLink to="/public">Go to public elections</TextLink></>} /></Route>
  </Routes>;
  return settings.votingEnabled ? <VotingProvider pin={settings.authorityPin ?? ''}>{routes}</VotingProvider> : routes;
}
export class AppBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed ? <main className="fatal-error"><h1>We couldn’t display this workspace.</h1><p>Refresh to start a new local session.</p><a href="/">Return to the workspace</a></main> : this.props.children;
  }
}

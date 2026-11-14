import { Component, type ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import type { AuthClient } from './api/auth';
import { SessionProvider } from './auth/session';
import { Shell } from './components/shell';
import { PageHeading, TextLink } from './components/ui';
import { config, type AppConfig } from './config';
import { AdminOverview, AdminSection } from './pages/admin';
import { AnonymousVoting, BulletinBoard, PublicOverview, PublicResults, VerifyReceipt } from './pages/public';
import { Credentials, ElectionDetail, Elections, Login, RequireSession, VoterOverview } from './pages/voter';

export function App({ settings = config, client }: { settings?: AppConfig; client?: AuthClient }) {
  return <Routes>
    <Route path="/" element={<Navigate to="/voter" replace />} />
    <Route path="/voter" element={<SessionProvider enabled={settings.authEnabled} {...(client ? { client } : {})}><Shell workspace="voter" /></SessionProvider>}>
      <Route path="login" element={<Login />} />
      <Route element={<RequireSession />}>
        <Route index element={<VoterOverview />} />
        <Route path="elections" element={<Elections />} />
        <Route path="elections/:electionId" element={<ElectionDetail />} />
        <Route path="credentials" element={<Credentials />} />
      </Route>
    </Route>
    <Route path="/admin" element={<Shell workspace="admin" />}>
      <Route index element={<AdminOverview />} /><Route path=":section" element={<AdminSection />} />
    </Route>
    <Route path="/public" element={<Shell workspace="public" />}>
      <Route index element={<PublicOverview />} /><Route path="results/:electionId" element={<PublicResults />} />
      <Route path="board" element={<BulletinBoard />} /><Route path="verify" element={<VerifyReceipt />} />
    </Route>
    <Route element={<Shell workspace="public" />}><Route path="/vote" element={<AnonymousVoting />} />
      <Route path="*" element={<><PageHeading eyebrow="PAGE NOT FOUND" title="This page isn’t available" description="Choose a workspace to continue." /><TextLink to="/public">Go to public elections</TextLink></>} /></Route>
  </Routes>;
}
export class AppBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed ? <main className="fatal-error"><h1>We couldn’t display this workspace.</h1><p>Refresh to start a new local session.</p><a href="/">Return to the workspace</a></main> : this.props.children;
  }
}

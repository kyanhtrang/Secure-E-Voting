import { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router';
import { Activity, ArrowUpRight, BarChart3, CalendarDays, Check, ChevronRight, ClipboardList, FileCheck2,
  Fingerprint, Globe2, KeyRound, LayoutDashboard, ListChecks, LockKeyhole, Menu, ShieldCheck, Users, X } from 'lucide-react';

export type Workspace = 'voter' | 'admin' | 'public';
const workspaces = { voter: { title: 'Voter workspace', subtitle: 'Your participation, protected' },
  admin: { title: 'Administration', subtitle: 'Election operations workspace' },
  public: { title: 'Public transparency', subtitle: 'Results you can inspect' } };
const links = {
  voter: [{ to: '/voter', text: 'Overview', icon: LayoutDashboard }, { to: '/voter/elections', text: 'Elections', icon: CalendarDays },
    { to: '/voter/credentials', text: 'Voting credential', icon: KeyRound }],
  admin: [{ to: '/admin', text: 'Overview', icon: LayoutDashboard }, { to: '/admin/elections', text: 'Election management', icon: CalendarDays },
    { to: '/admin/candidates', text: 'Candidates', icon: Users }, { to: '/admin/status', text: 'Election status', icon: Activity },
    { to: '/admin/tally', text: 'Tally management', icon: BarChart3 }, { to: '/admin/publication', text: 'Publication', icon: FileCheck2 },
    { to: '/admin/audit', text: 'Audit overview', icon: ClipboardList }],
  public: [{ to: '/public', text: 'Published elections', icon: Globe2 }, { to: '/public/board', text: 'Bulletin board', icon: ListChecks },
    { to: '/public/verify', text: 'Verify a receipt', icon: Fingerprint }],
};
export function Shell({ workspace }: { workspace: Workspace }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const location = useLocation();
  useEffect(() => {
    if (menuOpen) document.querySelector<HTMLElement>('#workspace-navigation nav a')?.focus();
  }, [menuOpen]);
  useEffect(() => {
    setMenuOpen(false);
    const heading = document.querySelector<HTMLElement>('main h1');
    if (heading) { document.title = heading.textContent + ' · Secure E-Voting'; heading.focus({ preventScroll: true }); }
  }, [location.pathname]);
  const info = workspaces[workspace];
  return <div className="app-shell">
    <a className="skip-link" href="#main">Skip to content</a>
    <aside className={`sidebar ${menuOpen ? 'is-open' : ''}`} id="workspace-navigation" aria-label="Workspace"
      onKeyDown={event => { if (event.key === 'Escape' && menuOpen) { setMenuOpen(false); menuButton.current?.focus(); } }}>
      <NavLink to="/" className="brand" aria-label="Secure E-Voting home"><span className="brand-mark"><ShieldCheck size={25} aria-hidden="true" /></span>
        <span>Secure<span className="brand-second">E-Voting</span></span></NavLink>
      <div className="sidebar-label">WORKSPACE</div>
      <div className="workspace-name"><span className="workspace-symbol">{workspace === 'voter' ? <Users size={17} /> : workspace === 'admin' ? <LockKeyhole size={17} /> : <Globe2 size={17} />}</span>
        <div>{info.title}<small>{workspace === 'admin' ? 'Foundation · read only' : workspace === 'public' ? 'No sign-in required' : 'Local research demo'}</small></div></div>
      <nav aria-label={info.title}>{links[workspace].map(({ to, text, icon: Icon }) =>
        <NavLink key={to} to={to} end={to === '/'+workspace} className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}>
          <Icon size={18} aria-hidden="true" /><span>{text}</span><ChevronRight size={14} aria-hidden="true" /></NavLink>)}</nav>
      <div className="sidebar-bottom">
        <div className="sidebar-research"><span className="research-icon"><ShieldCheck size={21} aria-hidden="true" /></span>
          <strong>Built on verifiable trust</strong><p>A cryptography research project exploring private, accountable elections.</p>
          <span className="research-rule"><Check size={13} aria-hidden="true" /> RFC 9474 protocol foundation</span></div>
        <span className="version-label"><span /> LOCAL DEMO <span className="version">v0.1</span></span>
      </div>
    </aside>
    <div className="main-frame">
      <header className="topbar">
        <button ref={menuButton} className="menu-toggle" aria-label={menuOpen ? 'Close navigation' : 'Open navigation'} aria-expanded={menuOpen}
          aria-controls="workspace-navigation" onClick={() => setMenuOpen(value => !value)}>{menuOpen ? <X size={22} /> : <Menu size={22} />}</button>
        <div className="breadcrumb"><span>Secure E-Voting</span><ChevronRight size={14} aria-hidden="true" /><strong>{info.title}</strong></div>
        <nav className="audience-nav" aria-label="Choose workspace">
          <NavLink to="/voter" className={workspace === 'voter' ? 'selected' : ''}>Voter</NavLink>
          <NavLink to="/admin" className={workspace === 'admin' ? 'selected' : ''}>Admin</NavLink>
          <NavLink to="/public" className={workspace === 'public' ? 'selected' : ''}>Public<ArrowUpRight size={13} aria-hidden="true" /></NavLink>
        </nav>
      </header>
      <main id="main" tabIndex={-1} className="page-content"><Outlet /></main>
      <footer className="site-footer"><span>Secure E-Voting <span aria-hidden="true">/</span> Research MVP</span>
        <span><LockKeyhole size={12} aria-hidden="true" /> Local demonstration environment</span></footer>
    </div>
  </div>;
}

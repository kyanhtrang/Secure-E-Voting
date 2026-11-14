import { ArrowRight, CircleDashed, LockKeyhole, LoaderCircle, ShieldCheck, type LucideIcon } from 'lucide-react';
import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { Link } from 'react-router';

export function Button({ children, secondary = false, busy = false, className = '', ...props }:
  ButtonHTMLAttributes<HTMLButtonElement> & { secondary?: boolean; busy?: boolean }) {
  return <button className={`button ${secondary ? 'button-secondary' : ''} ${className}`} {...props} aria-busy={busy || undefined}>
    {busy && <LoaderCircle size={16} className="spin" aria-hidden="true" />}{children}
  </button>;
}
export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'success' | 'amber' }) {
  return <span className={`badge badge-${tone}`}><span aria-hidden="true" />{children}</span>;
}
export function Banner({ children, tone = 'info' }: { children: ReactNode; tone?: 'info' | 'warning' | 'success' | 'error' }) {
  return <div className={`banner banner-${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
    <ShieldCheck size={19} aria-hidden="true" /><div>{children}</div>
  </div>;
}
export function PageHeading({ eyebrow, title, description, children }: { eyebrow: string; title: string; description: string; children?: ReactNode }) {
  return <header className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1 tabIndex={-1}>{title}</h1>
    <p>{description}</p></div>{children && <div className="heading-actions">{children}</div>}</header>;
}
export function Panel({ title, description, action, children, className = '' }: { title: string; description?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}><header className="panel-header"><div><h2>{title}</h2>{description && <p>{description}</p>}</div>{action}</header>{children}</section>;
}
export function EmptyState({ title, children, icon: Icon = CircleDashed, action }: { title: string; children: ReactNode; icon?: LucideIcon; action?: ReactNode }) {
  return <div className="empty-state"><div className="empty-icon"><Icon size={26} aria-hidden="true" /></div>
    <h3>{title}</h3><p>{children}</p>{action}</div>;
}
export function Loading({ children = 'Checking your session…' }: { children?: ReactNode }) {
  return <div className="loading-state" role="status"><LoaderCircle size={23} className="spin" aria-hidden="true" /><span>{children}</span></div>;
}
export function TextLink({ to, children }: { to: string; children: ReactNode }) {
  return <Link className="text-link" to={to}>{children}<ArrowRight size={16} aria-hidden="true" /></Link>;
}
export function BoundaryNote({ children }: { children: ReactNode }) {
  return <div className="boundary-note"><LockKeyhole size={18} aria-hidden="true" /><p>{children}</p></div>;
}
export function UnavailableTotals() {
  return <div className="metrics" aria-label="Publication totals unavailable">
    {['Accepted ballots', 'Valid ballots', 'Invalid ballots', 'Counted ballots'].map(label =>
      <div className="metric" key={label}><span>{label}</span><strong aria-label="Not published">—</strong><small>Awaiting published evidence</small></div>)}
  </div>;
}
export function PublicationGate({ status, children, fallback }: { status: unknown; children: ReactNode; fallback: ReactNode }) {
  // Only a future authenticated publication source may supply this state.
  // Never derive it from query parameters, route IDs or voter authentication.
  return <>{status === 'PUBLISHED' ? children : fallback}</>;
}

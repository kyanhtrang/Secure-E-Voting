import { Activity, BarChart3, CalendarDays, ClipboardList, FileCheck2, LockKeyhole, Users } from 'lucide-react';
import { Link, useParams } from 'react-router';
import { Badge, Banner, Button, EmptyState, PageHeading, Panel } from '../components/ui';

const sections = {
  elections: { title: 'Election management', description: 'Create and configure elections through authorized administrative services.', icon: CalendarDays, action: 'Create election' },
  candidates: { title: 'Candidate management', description: 'Manage the candidate roster for a selected election.', icon: Users, action: 'Add candidate' },
  status: { title: 'Election status', description: 'Inspect lifecycle state and authorized opening and closing decisions.', icon: Activity, action: 'Open election' },
  tally: { title: 'Tally management', description: 'Review tally readiness and authorized decryption and counting operations.', icon: BarChart3, action: 'Start tally' },
  publication: { title: 'Publication management', description: 'Publish signed, verified election outcomes when authorized.', icon: FileCheck2, action: 'Publish results' },
  audit: { title: 'Audit overview', description: 'Review authorized operational evidence within the appropriate trust boundary.', icon: ClipboardList, action: 'Export audit' },
};
function AdminNotice() {
  return <Banner tone="warning"><strong>Read-only foundation.</strong> Administrator authorization and management APIs are not connected. Voter sign-in does not grant administrator privileges.</Banner>;
}
export function AdminOverview() {
  return <>
    <PageHeading eyebrow="ADMINISTRATION" title="An accountable election lifecycle." description="A foundation for authorized election operations, from configuration to publication."><Badge tone="amber">Foundation only</Badge></PageHeading>
    <AdminNotice />
    <div className="admin-grid">{Object.entries(sections).map(([key, item]) => <Link to={'/admin/'+key} className="admin-tile" key={key}>
      <span className="tile-icon"><item.icon size={23} aria-hidden="true" /></span><h2>{item.title}</h2><p>{item.description}</p><span className="tile-foot">Explore workspace <span aria-hidden="true">↗</span></span>
    </Link>)}</div>
    <Panel title="Planned election lifecycle" description="Reference workflow · no election is selected"><ol className="lifecycle">{['Draft', 'Open', 'Closed', 'Tallied', 'Published'].map((item, index) =>
      <li key={item}><span>{String(index+1).padStart(2, '0')}</span><strong>{item}</strong></li>)}</ol></Panel>
  </>;
}
export function AdminSection() {
  const { section } = useParams();
  const item = sections[section as keyof typeof sections];
  if (!item) return <AdminOverview />;
  return <>
    <PageHeading eyebrow="ADMINISTRATION" title={item.title} description={item.description}><Button disabled>{item.action}</Button></PageHeading>
    <AdminNotice />
    <Panel title="Workspace readiness" action={<Badge>Authorization required</Badge>}><EmptyState icon={item.icon} title="No authorized service is connected">
      A server-side administrator identity, an authorized API, and verified election data are required. This screen does not perform privileged operations.
    </EmptyState></Panel>
    {section === 'status' && <div className="inline-actions"><Button disabled>Open election</Button><Button secondary disabled>Close election</Button></div>}
    <div className="requirement-row"><LockKeyhole size={19} aria-hidden="true" /><div><strong>Authorization is a backend responsibility</strong><p>Navigation and disabled controls are not access controls. Every future operation must be authorized by the server.</p></div></div>
  </>;
}

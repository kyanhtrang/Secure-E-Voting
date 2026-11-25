import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Link, MemoryRouter } from 'react-router';
import { expect, it, vi } from 'vitest';
import { config } from '../config';
import { canonical } from '../voting/crypto';
import { createAdminClient, PublicationFailure, type AdminClient, type Election } from './client';
import { AdminWorkspace } from './workspace';

const id = '11111111-1111-4111-8111-111111111111', other = '22222222-2222-4222-8222-222222222222';
const token = 'adm1.' + 'A'.repeat(43);
function acknowledgement() { return { status:'PUBLISHED', election_id:id, bundle_digest:'a'.repeat(64), publication:{signature:'A'.repeat(86),manifest:{
  manifest_version:1,election_id:id,election_config_digest:'a'.repeat(64),snapshot_digest:'b'.repeat(64),tally_report_digest:'c'.repeat(64),
  accepted_total:2,valid_total:2,invalid_total:0,counted_total:2,publication_key_id:'synthetic-publication',signature_algorithm:'Ed25519'}} }; }
function json(value: unknown) { return new Response(canonical(value),{headers:{'Content-Type':'application/json','Cache-Control':'no-store'}}); }
function transport(publish: () => Promise<Response> = async () => json(acknowledgement())) {
  return vi.fn(async (path: RequestInfo | URL) => {
    if (path === '/api/v1/admin/auth/login') return json({access_token:token,token_type:'bearer'});
    if (path === '/api/v1/admin/auth/me') return json({admin_id:id,role:'ELECTION_ADMIN'});
    if (path === '/api/v1/admin/auth/logout') return new Response(null,{status:204});
    if (path === '/api/v1/publication/elections/'+id+'/publish') return publish();
    throw new Error('Unexpected synthetic route');
  });
}
it('is disabled by default and refuses unauthenticated publication without any transport',async()=>{
  expect(config.publicationEnabled).toBe(false);
  const wire=transport(),client=createAdminClient(wire);
  await client.login('synthetic','synthetic-only');
  await expect(client.publish(id)).rejects.toBeInstanceOf(PublicationFailure);
  expect(wire).toHaveBeenCalledTimes(2);
  const anonymous=createAdminClient(wire,true);
  await expect(anonymous.publish(id)).rejects.toMatchObject({status:401});
  expect(wire).toHaveBeenCalledTimes(2);
});
it('uses only a fixed Publisher POST with the memory-only Admin bearer and safe fetch policies',async()=>{
  const wire=transport(),client=createAdminClient(wire,true);await client.login('synthetic','synthetic-only');
  expect(await client.publish(id)).toEqual(acknowledgement());
  const [path,options]=wire.mock.calls.at(-1)! as unknown as [string,RequestInit];
  expect(path).toBe('/api/v1/publication/elections/'+id+'/publish');
  expect(options).toMatchObject({method:'POST',body:'{}',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',headers:{Authorization:'Bearer '+token}});
  expect(localStorage.length).toBe(0);expect(sessionStorage.length).toBe(0);
  await client.logout();await expect(client.publish(id)).rejects.toMatchObject({status:401});
});
it.each(['https://external.test','../vote/ballots',id+'\n',id.replace('11111111','AAAAAAAA')])('rejects noncanonical election path %s',async bad=>{
  const wire=transport(),client=createAdminClient(wire,true);await client.login('synthetic','synthetic-only');
  await expect(client.publish(bad)).rejects.toMatchObject({status:422});expect(wire).toHaveBeenCalledTimes(2);
});
it.each([401,403,409,422,503])('sanitizes Publisher HTTP %s and clears authorization on 401',async status=>{
  const wire=transport(async()=>new Response('SECRET_CANARY',{status})),client=createAdminClient(wire,true);await client.login('synthetic','synthetic-only');
  await expect(client.publish(id)).rejects.toMatchObject({status,uncertain:status===503});
  try { await client.publish(id); } catch (error) { expect(String(error)).not.toContain('SECRET_CANARY'); }
  if(status===401)expect(wire).toHaveBeenCalledTimes(3);
});
it('bounds responses, rejects extra fields/noncanonical JSON and does not expose raw errors',async()=>{
  for(const body of [' '.repeat(8193),JSON.stringify(acknowledgement()),'{"secret":"SECRET_CANARY"}',JSON.stringify({...acknowledgement(),extra:true})]){
    const client=createAdminClient(transport(async()=>new Response(body,{headers:{'Content-Type':'application/json','Cache-Control':'no-store'}})),true);
    await client.login('synthetic','synthetic-only');await expect(client.publish(id)).rejects.toMatchObject({status:503,uncertain:true});
  }
});
it('blocks duplicate in-flight requests and discards acknowledgements after forget',async()=>{
  let release!:(response:Response)=>void;
  const wire=transport(()=>new Promise(resolve=>{release=resolve;})),client=createAdminClient(wire,true);
  await client.login('synthetic','synthetic-only');const first=client.publish(id);
  await expect(client.publish(id)).rejects.toMatchObject({status:409});client.forget();release(json(acknowledgement()));
  await expect(first).rejects.toMatchObject({status:401});expect(wire).toHaveBeenCalledTimes(3);
});
it('cancels an unread error stream instead of consuming sensitive or unbounded bodies',async()=>{
  const cancelled=vi.fn();
  const client=createAdminClient(transport(async()=>new Response(new ReadableStream({cancel:cancelled}),{status:503})),true);
  await client.login('synthetic','synthetic-only');await expect(client.publish(id)).rejects.toMatchObject({status:503,uncertain:true});
  expect(cancelled).toHaveBeenCalledTimes(1);
});
it('aborts with an unknown outcome after the bounded timeout',async()=>{
  vi.useFakeTimers();
  try {
    const wire=transport();
    const fetcher=vi.fn(async (...args:Parameters<typeof fetch>)=>{
      if(!String(args[0]).startsWith('/api/v1/publication/'))return wire(args[0]);
      return new Promise<Response>((_,reject)=>args[1]!.signal!.addEventListener('abort',()=>reject(new Error('SECRET_CANARY'))));
    });
    const client=createAdminClient(fetcher,true);await client.login('synthetic','synthetic-only');
    const request=expect(client.publish(id)).rejects.toMatchObject({status:503,uncertain:true});
    await vi.advanceTimersByTimeAsync(30000);await request;
  } finally { vi.useRealTimers(); }
});

function election(election_id=id): Election { return {election_id,title:election_id===id?'Synthetic first':'Synthetic second',status:'TALLIED',phase:'TALLIED',revision:1,
  opens_at:'2026-01-01T00:00:00Z',closes_at:'2026-01-02T00:00:00Z',ra_ready:true,keyset_id:'synthetic',config_hash:'a'.repeat(64),candidates:[],bundle:null}; }
function fixture() {
  const rows=[election(),election(other)];
  const client={login:vi.fn(),forget:vi.fn(),logout:vi.fn(),list:vi.fn(async()=>({elections:rows.map(row=>({...row}))})),keys:vi.fn(async()=>({keysets:[]})),
    detail:vi.fn(async(key:string)=>({...rows.find(row=>row.election_id===key)!})),audit:vi.fn(async()=>({events:[]})),publish:vi.fn(async()=>acknowledgement())} as unknown as AdminClient;
  return {rows,client};
}
async function open(client:AdminClient, enabled=true) {
  render(<MemoryRouter initialEntries={['/admin/publication']}><Link to="/admin/status">Other route</Link><Link to="/admin/publication">Return to publication</Link><AdminWorkspace client={client} publicationEnabled={enabled}/></MemoryRouter>);
  expect(screen.queryByRole('button',{name:'Publish results'})).not.toBeInTheDocument();
  fireEvent.submit(screen.getByRole('button',{name:'Sign in as administrator'}).closest('form')!);
  fireEvent.click(await screen.findByRole('button',{name:'Synthetic first · TALLIED'}));
  await screen.findByRole('heading',{name:'Publish election results'});
  await waitFor(()=>expect(screen.getByRole('button',{name:'Refresh publication status'})).toBeEnabled());
}
async function confirm() {fireEvent.click(screen.getByRole('button',{name:'Publish results'}));fireEvent.click(screen.getByRole('button',{name:'Confirm publish'}));}
it('shows disabled configuration and requires a TALLIED reconciled election',async()=>{
  const {client}=fixture();await open(client,false);expect(screen.getByRole('button',{name:'Publish results'})).toBeDisabled();
});
it.each(['OPEN','CLOSED','TALLIED_UNREADY'])('never enables publication for %s',async state=>{
  const {client,rows}=fixture();rows[0]!.phase=state==='TALLIED_UNREADY'?'TALLIED':state;rows[0]!.ra_ready=false;
  await open(client);expect(screen.getByRole('button',{name:'Publish results'})).toBeDisabled();
});
it('requires a second confirmation; cancellation, election switch and route change never publish',async()=>{
  const {client}=fixture();await open(client);
  fireEvent.click(screen.getByRole('button',{name:'Publish results'}));expect(client.publish).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button',{name:'Cancel publication'}));expect(client.publish).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button',{name:'Publish results'}));fireEvent.click(screen.getByRole('button',{name:'Synthetic second · TALLIED'}));
  await screen.findByRole('heading',{name:'Synthetic second'});expect(screen.queryByRole('button',{name:'Confirm publish'})).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Publish results'}));fireEvent.click(screen.getByRole('link',{name:'Other route'}));
  fireEvent.click(screen.getByRole('link',{name:'Return to publication'}));expect(screen.queryByRole('button',{name:'Confirm publish'})).not.toBeInTheDocument();
  expect(client.publish).not.toHaveBeenCalled();
});
it('refreshes committed state after response loss without retry and links to public verification',async()=>{
  const {client,rows}=fixture();vi.mocked(client.publish).mockImplementation(async()=>{rows[0]!.phase=rows[0]!.status='PUBLISHED';throw new PublicationFailure(503,true);});
  await open(client);await confirm();expect(await screen.findByText('PUBLISHED — publication is committed.')).toBeInTheDocument();
  expect(screen.getByRole('link',{name:'Open public results and independent verification'})).toHaveAttribute('href','/public/results/'+id);
  expect(client.publish).toHaveBeenCalledTimes(1);
});
it('refreshes successful publication and prevents synchronous double confirmation',async()=>{
  const {client,rows}=fixture();let release!:()=>void;
  vi.mocked(client.publish).mockImplementation(()=>new Promise(resolve=>{release=()=>{rows[0]!.phase=rows[0]!.status='PUBLISHED';resolve(acknowledgement() as never);};}));
  await open(client);fireEvent.click(screen.getByRole('button',{name:'Publish results'}));const button=screen.getByRole('button',{name:'Confirm publish'});
  fireEvent.click(button);fireEvent.click(button);expect(client.publish).toHaveBeenCalledTimes(1);
  await act(async()=>release());await screen.findByText('PUBLISHED — publication is committed.');
});
it.each([401,403,409,503])('handles UI publication error %s without echoing sensitive data',async status=>{
  const {client}=fixture();vi.mocked(client.publish).mockRejectedValue(new PublicationFailure(status,status===503));
  await open(client);await confirm();
  if(status===401){await screen.findByRole('heading',{name:'Administrator sign-in'});expect(client.forget).toHaveBeenCalled();}
  else {await screen.findByRole('alert');if(status===503)expect(screen.getByRole('button',{name:'Publish results'})).toBeDisabled();}
  expect(client.publish).toHaveBeenCalledTimes(1);
});
it('keeps an unconfirmed outcome blocked until an explicit state refresh and a new confirmation',async()=>{
  const {client}=fixture();vi.mocked(client.publish).mockRejectedValue(new PublicationFailure(503,true));await open(client);await confirm();
  await screen.findByText(/Publication outcome is unknown/);expect(screen.getByRole('button',{name:'Publish results'})).toBeDisabled();
  fireEvent.click(screen.getByRole('button',{name:'Refresh publication status'}));await waitFor(()=>expect(screen.getByRole('button',{name:'Publish results'})).toBeEnabled());
  expect(client.publish).toHaveBeenCalledTimes(1);expect(screen.queryByRole('button',{name:'Confirm publish'})).not.toBeInTheDocument();
});
it('logout clears authorization and pending confirmation',async()=>{
  const {client}=fixture();await open(client);fireEvent.click(screen.getByRole('button',{name:'Publish results'}));fireEvent.click(screen.getByRole('button',{name:'Admin logout'}));
  await screen.findByRole('heading',{name:'Administrator sign-in'});expect(screen.queryByRole('button',{name:'Confirm publish'})).not.toBeInTheDocument();expect(client.publish).not.toHaveBeenCalled();
});
it('discards an old-route publication result and requires fresh election selection on return',async()=>{
  const {client}=fixture();let release!:(value:never)=>void;
  vi.mocked(client.publish).mockImplementation(()=>new Promise(resolve=>{release=resolve;}));await open(client);await confirm();
  const details=vi.mocked(client.detail).mock.calls.length;
  fireEvent.click(screen.getByRole('link',{name:'Other route'}));
  await act(async()=>release(acknowledgement() as never));
  expect(client.detail).toHaveBeenCalledTimes(details);
  fireEvent.click(screen.getByRole('link',{name:'Return to publication'}));
  expect(screen.queryByRole('button',{name:'Publish results'})).not.toBeInTheDocument();
  expect(screen.queryByRole('button',{name:'Confirm publish'})).not.toBeInTheDocument();
  expect(client.publish).toHaveBeenCalledTimes(1);
});

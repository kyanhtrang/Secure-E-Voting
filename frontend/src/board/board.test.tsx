import { beforeAll,expect,it,vi } from 'vitest';
import { fireEvent,render,screen,waitFor } from '@testing-library/react';
import { MemoryRouter,Route,Routes } from 'react-router';
import { webcrypto } from 'node:crypto';
import { canonical } from '../voting/crypto';
import { boardFixture } from './fixtures.test-support';
import { PublicWorkspace } from './workspace';
import { boardGet } from './client';

let value:Awaited<ReturnType<typeof boardFixture>>;
beforeAll(async()=>{vi.stubGlobal('crypto',webcrypto);value=await boardFixture();},20000);
function result(data:unknown,status=200){return new Response(canonical(data),{status,headers:{'Cache-Control':'no-store','Content-Type':'application/json'}});}
function show(mode:'list'|'results'|'verify',pins=value.pins){return render(<MemoryRouter initialEntries={['/public/results/'+value.election]}><Routes><Route path="/public/results/:electionId" element={<PublicWorkspace mode={mode} pins={pins}/>} /></Routes></MemoryRouter>);}
it('renders totals only after real local cryptographic verification and omits all identity',async()=>{
  const fetcher=vi.fn().mockResolvedValue(result(value.bundle));vi.stubGlobal('fetch',fetcher);
  show('results');expect(screen.queryByText('Verified aggregate totals')).not.toBeInTheDocument();
  expect(await screen.findByText('Verified aggregate totals')).toBeInTheDocument();
  expect(screen.getByText('Synthetic TEST candidate: 1 (100.0%)')).toBeInTheDocument();
  for(const [path,options] of fetcher.mock.calls){expect(path).toMatch(/^\/api\/v1\/board\//);expect(options.credentials).toBe('omit');expect(options.headers.Authorization).toBeUndefined();}
  expect(localStorage.length).toBe(0);expect(sessionStorage.length).toBe(0);
});
it('labels missing pins and never displays counts',async()=>{
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(result(value.bundle)));
  show('results',{...value.pins,publication:''});
  expect(await screen.findByText(/UNVERIFIED:/)).toBeInTheDocument();expect(screen.queryByText('Verified aggregate totals')).not.toBeInTheDocument();
});
it('rejects tampered results instead of showing server-supplied counts',async()=>{
  const bad=structuredClone(value.bundle);bad.tally.report.counted_total=999;
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(result(bad)));show('results');
  expect(await screen.findByText(/INVALID:/)).toBeInTheDocument();expect(screen.queryByText('999')).not.toBeInTheDocument();
});
it('shows honest empty and unavailable feeds',async()=>{
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(result({elections:[],next_cursor:null})));show('list');
  expect(await screen.findByText('No published elections')).toBeInTheDocument();
});
it('verifies receipt presence locally with no receipt in the fetch URL',async()=>{
  const fetcher=vi.fn().mockImplementation(async()=>result(value.bundle));vi.stubGlobal('fetch',fetcher);show('verify');
  fireEvent.change(screen.getByLabelText('Election ID'),{target:{value:value.election}});
  fireEvent.change(screen.getByLabelText('Receipt hash'),{target:{value:value.hash}});
  fireEvent.click(screen.getByRole('button',{name:'Verify receipt'}));
  expect(await screen.findByText(/VERIFIED:/)).toBeInTheDocument();
  expect(fetcher.mock.calls.every(([path])=>!path.includes(value.hash))).toBe(true);
  fireEvent.change(screen.getByLabelText('Receipt hash'),{target:{value:'0'.repeat(64)}});
  fireEvent.click(screen.getByRole('button',{name:'Verify receipt'}));
  expect(await screen.findByText(/NOT_FOUND:/)).toBeInTheDocument();
});
it('does not equate unavailable publication with a missing receipt',async()=>{
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(result({code:'NOT_FOUND'},404)));show('results');
  expect(await screen.findByText(/UNAVAILABLE:/)).toBeInTheDocument();
});
it('rejects duplicate/noncanonical JSON and external API paths',async()=>{
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response('{"value":1,"value":2}')));
  await expect(boardGet('/api/v1/board')).rejects.toThrow();
  await expect(boardGet('/api/v1/ra/auth/me')).rejects.toThrow();
  await waitFor(()=>expect(screen.queryByText('Verified aggregate totals')).not.toBeInTheDocument());
});

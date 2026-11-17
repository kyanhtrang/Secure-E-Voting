import { beforeAll, afterAll, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { webcrypto } from 'node:crypto';
import { App } from '../app';
import { ApiError, type AuthClient } from '../api/auth';
import { testMaterial } from '../voting/material.test-support';

let material:Awaited<ReturnType<typeof testMaterial>>;
beforeAll(async()=>{vi.stubGlobal('crypto',webcrypto);material=await testMaterial();});
afterAll(()=>vi.unstubAllGlobals());
async function mount(data:Promise<unknown>, path='/voter/login') {
  const client:AuthClient={login:vi.fn().mockResolvedValue({voter_id:crypto.randomUUID()}),me:vi.fn(),logout:vi.fn(),forget:vi.fn(),elections:vi.fn(()=>data),issue:vi.fn()};
  render(<MemoryRouter initialEntries={[path]}><App settings={{authEnabled:true,votingEnabled:true,authorityPin:material.pin}} client={client} /></MemoryRouter>);
  const user=userEvent.setup();
  if(path==='/voter/login') {
    await user.type(screen.getByLabelText('Username'),'synthetic');await user.type(screen.getByLabelText('Password'),'synthetic');await user.click(screen.getByRole('button',{name:'Sign in securely'}));
    await screen.findByText('Session verified');await user.click(screen.getByRole('link',{name:'Elections'}));
  }
  return {client,user};
}
function catalogue() { return {elections:[{election_id:material.bundle.manifest.election_id,bundle:material.bundle,eligibility:'checked_on_issue',credential_availability:'checked_on_issue'}]}; }
it('shows real catalogue loading and an honest empty state',async()=>{
  let resolve!:(value:unknown)=>void;await mount(new Promise(value=>{resolve=value;}));
  expect(screen.getByText('Verifying election configurations…')).toBeInTheDocument();resolve({elections:[]});
  expect(await screen.findByText('No elections have been published')).toBeInTheDocument();
});
it('displays verified candidates and requires explicit selection and confirmation',async()=>{
  const {user}=await mount(Promise.resolve(catalogue()));
  await user.click(await screen.findByRole('link',{name:'View candidates & participation'}));
  const candidate=await screen.findByRole('radio',{name:/Synthetic TEST candidate/});
  expect(screen.getByRole('button',{name:'Protect & prepare credential'})).toBeDisabled();
  await user.click(candidate);await user.click(screen.getByRole('checkbox',{name:/I confirm this candidate/}));
  expect(screen.getByRole('button',{name:'Protect & prepare credential'})).toBeEnabled();
  expect(screen.getByText('Voting checks its database on submission')).toBeInTheDocument();
});
it('fails closed when manifest verification fails',async()=>{
  const rows=catalogue();rows.elections[0]!.bundle=structuredClone(material.bundle);rows.elections[0]!.bundle.manifest.candidates[0]!.candidate_name='Modified';
  await mount(Promise.resolve(rows));
  expect(await screen.findByRole('alert')).toHaveTextContent('Verification or protected storage failed');
  expect(screen.queryByRole('link',{name:'View candidates & participation'})).not.toBeInTheDocument();
});
it('sanitizes catalogue service errors and keeps anonymous pages out of RA context',async()=>{
  let reject!:(error:unknown)=>void;const deferred=new Promise<unknown>((_,fail)=>{reject=fail;});
  await mount(deferred);reject(new ApiError('unavailable'));expect(await screen.findByRole('alert')).toHaveTextContent('local RA service is unavailable');
});
it('anonymous route calls no authenticated RA method',async()=>{
  const {client}=await mount(Promise.resolve(catalogue()),'/vote');
  expect(screen.getByRole('heading',{name:'Submit your sealed ballot'})).toBeInTheDocument();
  expect(client.login).not.toHaveBeenCalled();expect(client.elections).not.toHaveBeenCalled();expect(client.issue).not.toHaveBeenCalled();
});

// @vitest-environment node
import { expect, it, vi } from 'vitest';
import { createAuthClient } from '../api/auth';
import { separateVotingTarget } from '../../vite.config';

it('keeps scoped RA authorization private and reconstructs only the allowed issuance fields',async()=>{
  const token='A'.repeat(43), requests:{url:string;options:RequestInit}[]=[];
  const fetcher=vi.fn<typeof fetch>().mockImplementation(async(url,options)=>{
    requests.push({url:String(url),options:options!});
    const body=String(url).endsWith('/login') ? {access_token:token,token_type:'Bearer'} : String(url).endsWith('/me') ? {voter_id:'11111111-1111-4111-8111-111111111111'} : {};
    return new Response(JSON.stringify(body),{status:200});
  });
  const auth=createAuthClient(true,fetcher);await auth.login('synthetic','synthetic');
  await auth.elections();await auth.issue({election_id:'election',request_id:'request',blinded_msg:'blinded',...{serial:'PRIVATE_SERIAL_CANARY',candidate_id:'PRIVATE_CHOICE_CANARY'}});
  const issued=requests.at(-1)!;
  expect(issued.url).toBe('/api/v1/ra/credentials/issue');
  expect(JSON.parse(String(issued.options.body))).toEqual({election_id:'election',request_id:'request',blinded_msg:'blinded'});
  expect(issued.options.credentials).toBe('omit');expect(issued.options.headers).toHaveProperty('Authorization','Bearer '+token);
  expect(Object.keys(auth)).not.toContain('token');expect(Object.keys(auth)).not.toContain('bearer');
});
it('refuses routing Voting to the RA loopback port, including a hostname alias',()=>{
  expect(()=>separateVotingTarget('http://127.0.0.1:8000','http://localhost:8000')).toThrow();
  expect(()=>separateVotingTarget('http://127.0.0.1:8000','https://remote.invalid')).toThrow();
  expect(separateVotingTarget('http://127.0.0.1:8000','http://127.0.0.1:8001')).toBe('http://127.0.0.1:8001');
});

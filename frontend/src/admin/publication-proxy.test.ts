// @vitest-environment node
import type { IncomingMessage } from 'node:http';
import { expect,it } from 'vitest';
import { publicationRequestStatus,publicationTarget } from '../../vite.config';

const path='/api/v1/publication/elections/11111111-1111-4111-8111-111111111111/publish';
function request(patch: Record<string,unknown>={}, headerPatch:Record<string,string|undefined>={}) {
  const headers={host:'127.0.0.1:5173',origin:'http://127.0.0.1:5173',authorization:'Bearer adm1.'+'A'.repeat(43),
    'content-length':'2','content-type':'application/json',...headerPatch};
  for(const key of Object.keys(headers))if(headers[key as keyof typeof headers]===undefined)delete headers[key as keyof typeof headers];
  return {url:path,method:'POST',headers,rawHeaders:Object.entries(headers).flatMap(([key,value])=>[key,value]),socket:{remoteAddress:'127.0.0.1'},...patch} as unknown as IncomingMessage;
}
it('requires explicit loopback target separated from every other service port',()=>{
  expect(publicationTarget('http://127.0.0.1:8007',['http://127.0.0.1:8002'])).toBe('http://127.0.0.1:8007');
  for(const value of [undefined,'https://remote.test','http://user:secret@localhost:8007','http://localhost:8007/path','http://localhost:8007?next=1'])
    expect(()=>publicationTarget(value,[])).toThrow();
  expect(()=>publicationTarget('http://localhost:8002',['http://127.0.0.1:8002'])).toThrow();
  expect(()=>publicationTarget('http://localhost',['http://127.0.0.1:80'])).toThrow();
});
it('passes only the exact bounded authenticated POST, preserving Host and Origin',()=>{
  const req=request();expect(publicationRequestStatus(req,true)).toBeNull();expect(req.headers.origin).toBe('http://'+req.headers.host);
  expect(publicationRequestStatus(req,false)).toBe(503);
});
it.each(['/api/v1/publication/elections/../publish',path+'?redirect=x',path+'/',path+'\n',path.replace('11111111','AAAAAAAA'),'/api/v1/publication/anything'])('refuses route %s',url=>{
  expect(publicationRequestStatus(request({url}),true)).toBe(404);
});
it.each(['GET','PUT','PATCH','DELETE','OPTIONS'])('never proxies method %s',method=>expect(publicationRequestStatus(request({method}),true)).toBe(405));
it.each(['https://external.test','http://localhost:5173','null'])('rejects a mismatched Origin %s',origin=>expect(publicationRequestStatus(request({}, {origin}),true)).toBe(403));
it('rejects remote callers, duplicate headers and non-Admin bearer formats',()=>{
  expect(publicationRequestStatus(request({socket:{remoteAddress:'192.0.2.1'}}),true)).toBe(403);
  const duplicate=request();duplicate.rawHeaders.push('Origin','http://127.0.0.1:5173');expect(publicationRequestStatus(duplicate,true)).toBe(403);
  for(const authorization of [undefined,'Bearer tly1.'+'A'.repeat(43),'Bearer '+'A'.repeat(43)])
    expect(publicationRequestStatus(request({}, {authorization}),true)).toBe(401);
});
it.each(['cookie','proxy-authorization','x-voter-id','x-ra-token','x-request-id','x-username','x-admin-token','x-admin-id','x-tally-token'])('rejects identity/cookie header %s without stripping',name=>{
  const req=request({}, {[name]:'SYNTHETIC_CANARY'});expect(publicationRequestStatus(req,true)).toBe(422);expect(req.headers[name]).toBe('SYNTHETIC_CANARY');
});
it.each([{'content-length':'129'},{'content-length':undefined},{'transfer-encoding':'chunked'},{'content-type':'text/plain'}])('rejects unbounded or incorrect request headers',headers=>{
  expect(publicationRequestStatus(request({},headers),true)).toBe(422);
});

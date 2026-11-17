// Transport regression only: this HTTP probe is not a Voting service or E2E PASS.
import { createServer } from 'node:http';
import { test, expect } from '@playwright/test';
import { withAnonymousForward } from '../anonymous-forward.mjs';

async function probe(run) {
  const posts=[];
  const server=createServer(async(req,res)=>{
    if(req.method==='GET'){res.end('<!doctype html><title>Anonymous transport probe</title>');return;}
    let body='';for await(const chunk of req)body+=chunk;
    posts.push({cookie:'cookie' in req.headers,authorization:'authorization' in req.headers,body,method:req.method});
    res.writeHead('cookie' in req.headers ? 400 : 201);res.end('{}');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try { await run('http://127.0.0.1:'+server.address().port,posts); }
  finally { server.closeAllConnections();await new Promise(resolve=>server.close(resolve)); }
}

test('isolated forwarding preserves original bytes and cookie omission while route.fetch reintroduces the browser cookie',async({page,context})=>{
  await probe(async(origin,posts)=>{
    await page.goto(origin);await context.addCookies([{name:'synthetic_canary',value:'transport-test-only',url:origin}]);
    let originalOmitted=false,rawStatus,isolatedStatus;
    await page.route('**/api/v1/vote/ballots',async route=>{
      originalOmitted=!(await route.request().allHeaders()).cookie;
      rawStatus=(await route.fetch()).status();await route.abort('failed');
    });
    const submit=()=>page.evaluate(()=>fetch('/api/v1/vote/ballots',{
      method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:'{"transport_probe":true}',
    }).catch(()=>{}));
    await submit();await page.unroute('**/api/v1/vote/ballots');
    await page.route('**/api/v1/vote/ballots',async route=>{
      await withAnonymousForward(route,async response=>{isolatedStatus=response.status();await route.abort('failed');});
    });
    await submit();
    expect(originalOmitted).toBe(true);expect(rawStatus).toBe(400);expect(isolatedStatus).toBe(201);
    expect(posts).toEqual([
      {cookie:true,authorization:false,body:'{"transport_probe":true}',method:'POST'},
      {cookie:false,authorization:false,body:'{"transport_probe":true}',method:'POST'},
    ]);
    expect((await context.cookies()).some(cookie=>cookie.name==='synthetic_canary')).toBe(true);
  });
});

for(const identity of ['cookie','authorization','x-voter-id']) {
  test('forwarding rejects original '+identity+' instead of stripping identity',async({page,context})=>{
    await probe(async(origin,posts)=>{
      await page.goto(origin);await context.addCookies([{name:'synthetic_canary',value:'transport-test-only',url:origin}]);
      let rejected=false;
      await page.route('**/api/v1/vote/ballots',async route=>{
        try { await withAnonymousForward(route,async()=>{}); }
        catch { rejected=true; }
        finally { await route.abort('failed'); }
      });
      await page.evaluate(identity=>fetch('/api/v1/vote/ballots',{
        method:'POST',credentials:identity==='cookie' ? 'include' : 'omit',
        headers:{'Content-Type':'application/json',...(identity==='cookie' ? {} : {[identity]:'synthetic-test-only'})},
        body:'{"transport_probe":true}',
      }).catch(()=>{}),identity);
      expect(rejected).toBe(true);expect(posts).toHaveLength(0);
    });
  });
}

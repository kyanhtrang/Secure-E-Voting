// UI fixture uses real cryptography and an explicitly synthetic store, not PostgreSQL.
import { expect,test } from '@playwright/test';
import canonicalize from 'canonicalize';
for(const width of [390,1440])test(`public verification, privacy and receipt checks at ${width}px`,async({page,context})=>{
  await page.setViewportSize({width,height:950});
  await context.addCookies([{name:'ra_identity_canary',value:'synthetic-only',url:'http://127.0.0.1:5191'}]);
  const calls:{path:string;headers:Record<string,string>}[]=[];
  page.on('request',request=>{if(new URL(request.url()).pathname.startsWith('/api/'))calls.push({path:new URL(request.url()).pathname,headers:request.headers()});});
  await page.goto('/public');
  const entry=page.getByRole('link',{name:/Election [0-9a-f-]+/});await expect(entry).toBeVisible();
  const href=(await entry.getAttribute('href'))!;await entry.click();
  await expect(page.getByRole('heading',{name:'Verified aggregate totals'})).toBeVisible();
  await expect(page.getByText(/VERIFIED:/)).toBeVisible();
  const election=href.split('/').at(-1)!;
  const hash=await page.evaluate(async id=>{
    const response=await fetch('/api/v1/board/'+id+'/evidence',{credentials:'omit',cache:'no-store'});
    return (await response.json()).snapshot.ballots[0].receipt_hash as string;
  },election);
  await page.goto('/public/verify');
  await page.getByLabel('Election ID').fill(election);await page.getByLabel('Receipt hash').fill(hash);
  await page.getByRole('button',{name:'Verify receipt',exact:true}).click();
  await expect(page.getByText(/VERIFIED:/)).toBeVisible();
  await page.getByLabel('Receipt hash').fill('0'.repeat(64));await page.getByRole('button',{name:'Verify receipt',exact:true}).click();
  await expect(page.getByText(/NOT_FOUND:/)).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  expect(calls.length).toBeGreaterThan(0);
  for(const call of calls){expect(call.path).toMatch(/^\/api\/v1\/board/);expect(call.headers).not.toHaveProperty('authorization');expect(call.headers).not.toHaveProperty('cookie');expect(call.path).not.toContain(hash);}
});
test('an altered public report cannot produce a verified results screen',async({page})=>{
  await page.goto('/public');const entry=page.getByRole('link',{name:/Election [0-9a-f-]+/});await expect(entry).toBeVisible();
  await page.route('**/api/v1/board/*/evidence',async route=>{
    const response=await route.fetch();const body=await response.json();body.tally.report.counted_total=999;
    await route.fulfill({status:200,contentType:'application/json',headers:{'Cache-Control':'no-store'},body:canonicalize(body)!});
  });
  await entry.click();await expect(page.getByText(/INVALID:/)).toBeVisible();
  await expect(page.getByRole('heading',{name:'Verified aggregate totals'})).toHaveCount(0);
});

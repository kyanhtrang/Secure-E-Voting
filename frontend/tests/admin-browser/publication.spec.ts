// Synthetic HTTP browser regressions. Hosted real Publisher execution is separate.
import { expect,test } from '@playwright/test';
import canonicalize from 'canonicalize';

for(const [width,loseResponse] of [[390,false],[1440,true]] as const) test(`publication confirmation and authoritative reconciliation at ${width}px`,async({page,context})=>{
  const id='11111111-1111-4111-8111-111111111111',token='adm1.'+'A'.repeat(43);
  let state='TALLIED',requests=0;
  await page.setViewportSize({width,height:950});
  await context.addCookies([{name:'identity_canary',value:'synthetic-only',url:'http://127.0.0.1:5177'}]);
  const election=()=>({election_id:id,title:'Synthetic publication election',status:state,phase:state,revision:1,ra_ready:true,
    opens_at:'2026-01-01T00:00:00Z',closes_at:'2026-01-02T00:00:00Z',keyset_id:'synthetic',config_hash:'a'.repeat(64),candidates:[],bundle:null});
  await page.route('**/api/v1/admin/**',async route=>{
    const path=new URL(route.request().url()).pathname;
    expect(route.request().headers()['cookie']).toBeUndefined();
    if(path.endsWith('/auth/login'))return route.fulfill({json:{access_token:token,token_type:'bearer'}});
    expect(route.request().headers()['authorization']).toBe('Bearer '+token);
    if(path.endsWith('/auth/me'))return route.fulfill({json:{admin_id:id,role:'ELECTION_ADMIN'}});
    if(path.endsWith('/auth/logout'))return route.fulfill({status:204});
    if(path.endsWith('/keysets'))return route.fulfill({json:{keysets:[]}});
    if(path.endsWith('/audit'))return route.fulfill({json:{events:[]}});
    return route.fulfill({json:path.endsWith('/elections')?{elections:[election()]}:election()});
  });
  await page.route('**/api/v1/publication/**',async route=>{
    requests++;expect(route.request().method()).toBe('POST');expect(route.request().postData()).toBe('{}');
    expect(route.request().headers()['authorization']).toBe('Bearer '+token);expect(route.request().headers()['cookie']).toBeUndefined();
    state='PUBLISHED';
    if(loseResponse)return route.abort('failed');
    return route.fulfill({status:200,contentType:'application/json',headers:{'Cache-Control':'no-store'},body:canonicalize({status:'PUBLISHED',election_id:id,bundle_digest:'a'.repeat(64),publication:{signature:'A'.repeat(86),manifest:{
      manifest_version:1,election_id:id,election_config_digest:'a'.repeat(64),snapshot_digest:'b'.repeat(64),tally_report_digest:'c'.repeat(64),
      accepted_total:2,valid_total:2,invalid_total:0,counted_total:2,publication_key_id:'synthetic',signature_algorithm:'Ed25519'}}})!});
  });
  await page.goto('/admin/publication');
  await page.getByLabel('Admin username').fill('synthetic');await page.getByLabel('Admin password').fill('synthetic-only');
  await page.getByRole('button',{name:'Sign in as administrator'}).click();
  await page.getByRole('button',{name:'Synthetic publication election · TALLIED'}).click();
  await page.getByRole('button',{name:'Publish results',exact:true}).click();expect(requests).toBe(0);
  await page.getByRole('button',{name:'Cancel publication'}).click();expect(requests).toBe(0);
  await page.getByRole('button',{name:'Publish results',exact:true}).click();await page.getByRole('button',{name:'Confirm publish'}).click();
  await expect(page.getByText('PUBLISHED — publication is committed.')).toBeVisible();expect(requests).toBe(1);
  await expect(page.getByRole('link',{name:'Open public results and independent verification'})).toHaveAttribute('href','/public/results/'+id);
  expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.getByRole('button',{name:'Admin logout'}).click();await expect(page.getByRole('heading',{name:'Administrator sign-in'})).toBeVisible();
});

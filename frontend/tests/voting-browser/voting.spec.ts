import { test, expect, type Page } from '@playwright/test';

async function prepare(page:Page,username='browser-test-voter-one') {
  await page.goto('/voter/login');await page.getByLabel('Username',{exact:true}).fill(username);await page.getByLabel('Password',{exact:true}).fill('Synthetic-Browser-Password');
  await page.getByRole('button',{name:'Sign in securely'}).click();
  await expect(page.getByRole('heading',{name:'Ready when your election is.'})).toBeVisible();
  const menu=page.getByRole('button',{name:'Open navigation'});if(await menu.isVisible())await menu.click();
  await page.getByRole('link',{name:'Elections',exact:true}).click();
  await page.getByRole('link',{name:'View candidates & participation'}).click();
  await page.getByRole('radio',{name:/Synthetic TEST candidate One/}).check();
  await page.getByRole('checkbox',{name:/I confirm this candidate/}).check();
  await page.getByLabel('Recovery passphrase',{exact:true}).fill('Synthetic browser recovery phrase');
  await page.getByRole('button',{name:'Protect & prepare credential'}).click();
  await page.getByRole('link',{name:'Open credential & recovery'}).click();
}
test('real browser blind/unblind, encrypted persistence, anonymous cookies omitted, verified receipt',async({page,context})=>{
  const issuance:unknown[]=[], anonymousHeaders:Record<string,string>[]=[];
  page.on('request',request=>{if(request.url().endsWith('/credentials/issue'))issuance.push(request.postDataJSON());});
  await prepare(page);
  const stored=await page.evaluate(async()=>{const db=await new Promise<IDBDatabase>((resolve,reject)=>{const request=indexedDB.open('secure-evoting-voter-recovery-v1');request.onsuccess=()=>resolve(request.result);request.onerror=reject;});const tx=db.transaction('pending'), request=tx.objectStore('pending').getAll();return await new Promise<unknown[]>(resolve=>{request.onsuccess=()=>resolve(request.result);});});
  expect(stored).toHaveLength(1);expect(Object.keys(stored[0] as object)).not.toContain('pending');
  await page.getByRole('button',{name:'Request / recover same credential'}).click();
  await page.getByRole('link',{name:'Continue to anonymous voting'}).click();
  expect(issuance).toHaveLength(1);expect(Object.keys(issuance[0] as object).sort()).toEqual(['blinded_msg','election_id','request_id']);
  await context.addCookies([{name:'ra_identity',value:'synthetic-cookie-canary',url:'http://127.0.0.1:5178'}]);
  await page.route('**/api/v1/vote/ballots',async route=>{anonymousHeaders.push(await route.request().allHeaders());await route.continue();});
  await page.getByRole('checkbox',{name:/I confirm submission/}).check();await page.getByRole('button',{name:'Submit ballot',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Your ballot was accepted.'})).toBeVisible();
  expect(anonymousHeaders).toHaveLength(1);expect(anonymousHeaders[0]).not.toHaveProperty('authorization');expect(anonymousHeaders[0]).not.toHaveProperty('cookie');
  await expect(page.getByLabel('Receipt hash')).toHaveValue(/^[0-9a-f]{64}$/);
  await expect(page.getByText('Accepted does not mean counted.',{exact:false})).toBeVisible();
});
test('lost commit response recovers same credential; mobile layout and navigation remain usable',async({page})=>{
  await page.setViewportSize({width:390,height:844});await prepare(page,'browser-test-voter-two');
  const issued:unknown[]=[];page.on('request',request=>{if(request.url().endsWith('/credentials/issue'))issued.push(request.postDataJSON());});
  await page.getByRole('button',{name:'Request / recover same credential'}).click();
  await page.getByRole('link',{name:'Continue to anonymous voting'}).click();
  await page.route('**/api/v1/vote/ballots',async route=>{await route.fetch();await route.abort('failed');});
  await page.getByRole('checkbox',{name:/I confirm submission/}).check();await page.getByRole('button',{name:'Submit ballot',exact:true}).click();
  await expect(page.getByText('Outcome uncertain',{exact:true})).toBeVisible();await page.getByRole('button',{name:'Check existing receipt'}).click();
  await expect(page.getByRole('heading',{name:'Your ballot was accepted.'})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  expect(issued).toHaveLength(1);
});
test('failed signing and expired RA session retain the exact protected request through reauthentication',async({page})=>{
  await prepare(page,'browser-test-voter-three');
  const bodies:unknown[]=[];
  let attempt=0;
  await page.route('**/api/v1/ra/credentials/issue',async route=>{
    bodies.push(route.request().postDataJSON());attempt++;
    if(attempt<3)await route.fulfill({status:attempt===1 ? 503 : 401,contentType:'application/json',body:'{}'});
    else await route.continue();
  });
  await page.getByRole('button',{name:'Request / recover same credential'}).click();
  await expect(page.getByRole('alert')).toContainText('service could not confirm');
  await page.getByRole('button',{name:'Request / recover same credential'}).click();
  await expect(page.getByRole('heading',{name:'A trusted place for your voice.'})).toBeVisible();
  await page.getByLabel('Username',{exact:true}).fill('browser-test-voter-three');await page.getByLabel('Password',{exact:true}).fill('Synthetic-Browser-Password');
  await page.getByRole('button',{name:'Sign in securely'}).click();
  await expect(page.getByRole('heading',{name:'Ready when your election is.'})).toBeVisible();
  await page.getByRole('link',{name:'Voting credential',exact:true}).click();
  await page.getByRole('button',{name:'Request / recover same credential'}).click();
  await expect(page.getByRole('link',{name:'Continue to anonymous voting'})).toBeVisible();
  expect(bodies).toHaveLength(3);expect(bodies[1]).toEqual(bodies[0]);expect(bodies[2]).toEqual(bodies[0]);
});

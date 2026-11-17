// Real-services-only Chromium driver. No HTTP response doubles or key generation.
// Private control/credentials use inherited pipes, never argv, env, reports or traces.
import { createInterface } from 'node:readline';
import { join, isAbsolute } from 'node:path';
import { chromium, expect } from '@playwright/test';
import { receipt, unb64 } from '../src/voting/crypto.ts';

const lines=createInterface({input:process.stdin,crlfDelay:Infinity})[Symbol.asyncIterator]();
async function read() {
  const result=await lines.next();
  if(result.done || result.value.length>8192)throw new Error('Control unavailable');
  return JSON.parse(result.value);
}
let stage='browser', browser;
async function checkpoint(event,receipt_hash) {
  stage=event;
  process.stdout.write(JSON.stringify({event,...(receipt_hash ? {receipt_hash} : {})})+'\n');
  const ack=await read();
  expect(ack).toEqual({ok:true});
}
try {
  if(!process.argv.includes('--real-services-only') || process.platform!=='linux'
     || process.env.GITHUB_ACTIONS!=='true' || process.env.RUNNER_ENVIRONMENT!=='github-hosted'
     || process.env.RUNNER_OS!=='Linux')throw new Error('Hosted Linux required');
  const config=await read(), origin=new URL(config.origin);
  expect(origin.protocol).toBe('http:');expect(origin.hostname).toBe('127.0.0.1');
  expect(['accepted','response_loss','closed_first']).toContain(config.scenario);
  expect(isAbsolute(config.screenshots)).toBe(true);
  browser=await chromium.launch();
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  const page=await context.newPage();page.setDefaultTimeout(20000);
  const issuance=[], anonymous=[];
  let badWire=false, login=0, me=0;
  page.on('request',request=>{
    const path=new URL(request.url()).pathname;
    try {
      if(path==='/api/v1/ra/auth/login')login++;
      if(path==='/api/v1/ra/auth/me')me++;
      if(path==='/api/v1/ra/credentials/issue') {
        const body=request.postDataJSON();
        expect(Object.keys(body).sort()).toEqual(['blinded_msg','election_id','request_id']);
        expect(unb64(body.blinded_msg,384)).toHaveLength(384);
        issuance.push(body);
      }
      if(path.startsWith('/api/v1/vote/')) {
        const headers=request.headers(),body=request.postDataJSON();
        for(const name of ['authorization','cookie','proxy-authorization','x-voter-id','x-ra-token','x-username','x-request-id'])expect(headers).not.toHaveProperty(name);
        expect(Object.keys(body).sort()).toEqual(['credential','election_id','envelope']);
        expect(Object.keys(body.credential).sort()).toEqual(['message','prepared_msg','signature']);
        expect(JSON.stringify(body)).not.toContain('request_id');
        expect(JSON.stringify(body)).not.toContain('voter_id');
        expect(JSON.stringify(body)).not.toContain(config.username);
        anonymous.push({path,body});
      }
    } catch { badWire=true; }
  });
  await page.goto(config.origin+'/voter/login');
  await page.getByLabel('Username',{exact:true}).fill(config.username);
  await page.getByLabel('Password',{exact:true}).fill(config.password);
  await page.getByRole('button',{name:'Sign in securely'}).click();
  await expect(page.getByRole('heading',{name:'Ready when your election is.'})).toBeVisible();
  expect(login).toBe(1);expect(me).toBeGreaterThanOrEqual(1);
  await page.getByRole('link',{name:'Elections',exact:true}).click();
  await expect(page.getByRole('link',{name:'View candidates & participation'})).toBeVisible();
  if(config.scenario==='accepted')await page.locator('main').screenshot({path:join(config.screenshots,'catalogue.png')});
  await checkpoint('catalogue');
  await page.getByRole('link',{name:'View candidates & participation'}).click();
  await expect(page.getByRole('radio')).toHaveCount(2);
  const candidate=page.getByRole('radio',{name:/Synthetic E2E candidate A/});
  const candidateId=await candidate.inputValue();
  await candidate.check();
  await page.getByRole('checkbox',{name:/I confirm this candidate/}).check();
  await page.getByLabel('Recovery passphrase',{exact:true}).fill(config.passphrase);
  await page.getByRole('button',{name:'Protect & prepare credential'}).click();
  await page.getByRole('link',{name:'Open credential & recovery'}).click();
  expect(issuance).toHaveLength(0);
  const protectedRecords=await page.evaluate(async()=>{
    const db=await new Promise((resolve,reject)=>{
      const request=indexedDB.open('secure-evoting-voter-recovery-v1');
      request.onsuccess=()=>resolve(request.result);request.onerror=reject;
    });
    try {
      const tx=db.transaction('pending'),request=tx.objectStore('pending').getAll();
      return await new Promise((resolve,reject)=>{tx.oncomplete=()=>resolve(request.result);tx.onerror=reject;});
    } finally { db.close(); }
  });
  expect(protectedRecords).toHaveLength(1);
  expect(Object.keys(protectedRecords[0]).sort()).toEqual(['ciphertext','context','iterations','kdf','nonce','salt','version']);
  expect(protectedRecords[0].context.election_id).toBe(config.election_id);
  await checkpoint('prepared');

  let originalBlindSignature;
  if(config.scenario==='response_loss') {
    await page.route('**/api/v1/ra/credentials/issue',async route=>{
      // Forward the ORIGINAL request to the REAL service. Drop only its response.
      const response=await route.fetch();expect(response.status()).toBe(201);
      originalBlindSignature=(await response.json()).blind_sig;
      await checkpoint('issuance_response_lost');await route.abort('failed');
    });
    await page.getByRole('button',{name:'Request / recover same credential'}).click();
    await expect(page.getByRole('alert')).toContainText('Verification or protected storage failed');
    await page.unroute('**/api/v1/ra/credentials/issue');
  }
  const issued=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/v1/ra/credentials/issue');
  await page.getByRole('button',{name:'Request / recover same credential'}).click();
  const issuedResponse=await issued;
  expect(issuedResponse.status()).toBe(config.scenario==='response_loss' ? 200 : 201);
  if(originalBlindSignature)expect((await issuedResponse.json()).blind_sig).toBe(originalBlindSignature);
  await expect(page.getByRole('link',{name:'Continue to anonymous voting'})).toBeVisible();
  expect(issuance).toHaveLength(config.scenario==='response_loss' ? 2 : 1);
  for(const request of issuance)expect(request).toEqual(issuance[0]);
  expect(issuance[0].election_id).toBe(config.election_id);
  await checkpoint('issued');
  await page.getByRole('link',{name:'Continue to anonymous voting'}).click();
  await context.addCookies([{name:'ra_identity_canary',value:'synthetic-private-cookie',url:config.origin}]);

  if(config.scenario==='closed_first')await checkpoint('before_submit_close');
  let committedReceipt;
  if(config.scenario==='response_loss') {
    await page.route('**/api/v1/vote/ballots',async route=>{
      const response=await route.fetch();expect(response.status()).toBe(201);
      committedReceipt=(await response.json()).receipt_hash;
      await checkpoint('committed_response_lost',committedReceipt);await route.abort('failed');
    });
  }
  const responsePromise=config.scenario==='response_loss' ? null : page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/vote/ballots');
  await page.getByRole('checkbox',{name:/I confirm submission/}).check();
  await page.getByRole('button',{name:'Submit ballot',exact:true}).click();
  if(config.scenario==='closed_first') {
    expect((await responsePromise).status()).toBe(409);
    await expect(page.getByRole('alert')).toContainText('election is closed');
    await checkpoint('rejected_closed');
  } else {
    if(config.scenario==='response_loss') {
      await expect(page.getByText('Outcome uncertain',{exact:true})).toBeVisible();
      await page.unroute('**/api/v1/vote/ballots');
      const recovered=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/vote/ballots/receipt');
      await page.getByRole('button',{name:'Check existing receipt'}).click();
      const response=await recovered;expect(response.status()).toBe(200);
      expect((await response.json()).receipt_hash).toBe(committedReceipt);
      await checkpoint('recovered',committedReceipt);
    } else {
      const response=await responsePromise;expect(response.status()).toBe(201);
      committedReceipt=(await response.json()).receipt_hash;
    }
    await expect(page.getByRole('heading',{name:'Your ballot was accepted.'})).toBeVisible();
    const payload=anonymous.find(value=>value.path==='/api/v1/vote/ballots').body;
    expect(await receipt(payload)).toBe(committedReceipt);
    await expect(page.getByLabel('Receipt hash')).toHaveValue(committedReceipt);
    if(config.scenario==='accepted')await page.getByRole('heading',{name:'Your ballot was accepted.'}).screenshot({path:join(config.screenshots,'accepted-heading.png')});
    await checkpoint('accepted',committedReceipt);
    async function post(body,recover=false) {
      return page.evaluate(async({body,recover})=>{
        const response=await fetch('/api/v1/vote/ballots'+(recover ? '/receipt' : ''),{
          method:'POST',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
          headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        return {status:response.status,data:await response.json()};
      },{body,recover});
    }
    expect((await post(payload)).status).toBe(409);
    const signature=structuredClone(payload);
    signature.credential.signature=(signature.credential.signature[0]==='A' ? 'B' : 'A')+signature.credential.signature.slice(1);
    expect((await post(signature)).status).toBe(422);
    const envelope=structuredClone(payload);
    envelope.envelope.ciphertext=(envelope.envelope.ciphertext[0]==='A' ? 'B' : 'A')+envelope.envelope.ciphertext.slice(1);
    expect((await post(envelope)).status).toBe(422);
    await checkpoint('security_checks',committedReceipt);
    await checkpoint('close_after_accept',committedReceipt);
    const recovered=await post(payload,true);
    expect(recovered.status).toBe(200);expect(recovered.data.receipt_hash).toBe(committedReceipt);
    await checkpoint('closed_recovery',committedReceipt);
  }
  const original=anonymous.find(value=>value.path==='/api/v1/vote/ballots').body;
  for(const request of issuance) {
    expect(JSON.stringify(request)).not.toContain(original.credential.message.serial);
    expect(JSON.stringify(request)).not.toContain(candidateId);
    expect(JSON.stringify(request)).not.toContain('Synthetic E2E candidate A');
    expect(request.blinded_msg).not.toBe(original.credential.prepared_msg);
  }
  expect(badWire).toBe(false);expect(anonymous.length).toBeGreaterThan(0);
  await context.close();await browser.close();browser=null;
  process.stdout.write('{"event":"done"}\n');
} catch {
  // Never emit Playwright expectation messages, DOM, request objects or stacks.
  process.stdout.write(JSON.stringify({event:'failure',stage})+'\n');
  process.exitCode=1;
} finally {
  if(browser)await browser.close().catch(()=>{});
  process.stdin.destroy();
}

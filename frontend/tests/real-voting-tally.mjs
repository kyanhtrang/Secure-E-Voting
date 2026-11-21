// Hosted real-services driver. No routes, response doubles, traces or artifacts.
// Keep individual choices and anonymous payloads inside this Chromium process.
import { createInterface } from 'node:readline';
import { chromium, expect } from '@playwright/test';
import { receipt, unb64 } from '../src/voting/crypto.ts';

const lines=createInterface({input:process.stdin,crlfDelay:Infinity})[Symbol.asyncIterator]();
const STAGES=new Set(['preflight','catalogue','prepare','issue','submit','security','recovery']);
async function read() {
  const result=await lines.next();
  if(result.done || result.value.length>8192)throw new Error('Bounded private control required');
  return JSON.parse(result.value);
}
function emit(value) { process.stdout.write(JSON.stringify(value)+'\n'); }
let browser, stage='preflight';
try {
  if(process.platform!=='linux' || process.env.GITHUB_ACTIONS!=='true'
    || process.env.RUNNER_ENVIRONMENT!=='github-hosted' || process.env.RUNNER_OS!=='Linux'
    || !process.argv.includes('--real-services-only'))throw new Error('Hosted Linux required');
  const config=await read(),origin=new URL(config.origin);
  expect(Object.keys(config).sort()).toEqual(['candidate','election_id','origin','passphrase','password','username']);
  expect(origin.protocol).toBe('http:');expect(origin.hostname).toBe('127.0.0.1');
  expect(origin.origin).toBe(config.origin);expect(['A','B']).toContain(config.candidate);
  browser=await chromium.launch();
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  const page=await context.newPage();page.setDefaultTimeout(20000);
  const issuance=[],anonymous=[];
  let badWire=false;
  page.on('request',request=>{
    try {
      const path=new URL(request.url()).pathname;
      if(path==='/api/v1/ra/credentials/issue') {
        const body=request.postDataJSON();
        expect(Object.keys(body).sort()).toEqual(['blinded_msg','election_id','request_id']);
        expect(unb64(body.blinded_msg,384)).toHaveLength(384);
        expect(body.election_id).toBe(config.election_id);issuance.push(body);
      }
      if(path.startsWith('/api/v1/vote/')) {
        const body=request.postDataJSON(),headers=request.headers();
        for(const name of ['authorization','cookie','proxy-authorization','x-voter-id','x-ra-token',
          'x-username','x-request-id','x-admin-token','x-admin-id'])expect(headers).not.toHaveProperty(name);
        expect(Object.keys(body).sort()).toEqual(['credential','election_id','envelope']);
        expect(Object.keys(body.credential).sort()).toEqual(['message','prepared_msg','signature']);
        for(const field of ['voter_id','request_id','username',config.username])expect(JSON.stringify(body)).not.toContain(field);
        anonymous.push({path,body});
      }
    } catch { badWire=true; }
  });
  stage='catalogue';
  await page.goto(config.origin+'/voter/login');
  await page.getByLabel('Username',{exact:true}).fill(config.username);
  await page.getByLabel('Password',{exact:true}).fill(config.password);
  await page.getByRole('button',{name:'Sign in securely'}).click();
  await expect(page.getByRole('heading',{name:'Ready when your election is.'})).toBeVisible();
  await page.getByRole('link',{name:'Elections',exact:true}).click();
  await page.getByRole('link',{name:'View candidates & participation'}).click();
  await expect(page.getByRole('radio')).toHaveCount(2);
  stage='prepare';
  const candidate=page.getByRole('radio',{name:new RegExp('Synthetic E2E candidate '+config.candidate)});
  const candidateId=await candidate.inputValue();
  await candidate.check();
  await page.getByRole('checkbox',{name:/I confirm this candidate/}).check();
  await page.getByLabel('Recovery passphrase',{exact:true}).fill(config.passphrase);
  await page.getByRole('button',{name:'Protect & prepare credential'}).click();
  await page.getByRole('link',{name:'Open credential & recovery'}).click();
  expect(issuance).toHaveLength(0);
  stage='issue';
  const issued=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/ra/credentials/issue');
  await page.getByRole('button',{name:'Request / recover same credential'}).click();
  expect((await issued).status()).toBe(201);
  await page.getByRole('link',{name:'Continue to anonymous voting'}).click();
  await expect(page).toHaveURL(config.origin+'/vote');
  await context.addCookies([{name:'ra_identity_canary',value:'synthetic-private-cookie',url:config.origin}]);
  stage='submit';
  const accepted=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/vote/ballots');
  await page.getByRole('checkbox',{name:/I confirm submission/}).check();
  await page.getByRole('button',{name:'Submit ballot',exact:true}).click();
  const response=await accepted;expect(response.status()).toBe(201);
  const hash=(await response.json()).receipt_hash;
  await expect(page.getByRole('heading',{name:'Your ballot was accepted.'})).toBeVisible();
  await expect(page.getByLabel('Receipt hash')).toHaveValue(hash);
  const payload=anonymous.find(v=>v.path==='/api/v1/vote/ballots').body;
  expect(await receipt(payload)).toBe(hash);
  expect(issuance).toHaveLength(1);
  for(const hidden of [payload.credential.message.serial,candidateId,'Synthetic E2E candidate'])
    expect(JSON.stringify(issuance[0])).not.toContain(hidden);
  expect(issuance[0].blinded_msg).not.toBe(payload.credential.prepared_msg);
  async function post(body,recover=false) {
    return page.evaluate(async({body,recover})=>{
      const response=await fetch('/api/v1/vote/ballots'+(recover ? '/receipt' : ''),{
        method:'POST',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
        headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      return {status:response.status,data:await response.json()};
    },{body,recover});
  }
  stage='security';
  expect((await post(payload)).status).toBe(409);
  const modified=structuredClone(payload);
  modified.credential.signature=(modified.credential.signature[0]==='A'?'B':'A')+modified.credential.signature.slice(1);
  expect((await post(modified)).status).toBe(422);
  const envelope=structuredClone(payload);
  envelope.envelope.ciphertext=(envelope.envelope.ciphertext[0]==='A'?'B':'A')+envelope.envelope.ciphertext.slice(1);
  expect((await post(envelope)).status).toBe(422);
  expect(badWire).toBe(false);
  emit({event:'accepted',receipt_hash:hash});
  // Coordinator closes/reconciles/runs Tally before acknowledging either voter.
  expect(await read()).toEqual({ok:true});
  stage='recovery';
  const recovered=await post(payload,true);
  expect(recovered.status).toBe(200);expect(recovered.data.receipt_hash).toBe(hash);
  expect((await post(payload)).status).toBe(409);
  expect(badWire).toBe(false);
  await context.close();await browser.close();browser=null;
  emit({event:'recovered'});
} catch {
  process.exitCode=1;
  emit({event:'failure',stage:STAGES.has(stage)?stage:'preflight'});
} finally {
  if(browser)await browser.close().catch(()=>{});
  process.stdin.destroy();
}

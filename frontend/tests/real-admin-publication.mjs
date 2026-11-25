// Hosted real services only. No routing mocks, keys, screenshots or raw errors.
import {createInterface} from 'node:readline';
import {createRequire} from 'node:module';
const require=createRequire(new URL('../package.json',import.meta.url));
const {chromium,expect}=require('@playwright/test');
const emit=value=>process.stdout.write(JSON.stringify(value)+'\n');
let stage='preflight',browser;
try {
  expect(process.platform).toBe('linux');expect(process.env.GITHUB_ACTIONS).toBe('true');
  expect(process.env.RUNNER_ENVIRONMENT).toBe('github-hosted');expect(process.argv.slice(2)).toEqual(['--real-services-only']);
  const input=createInterface({input:process.stdin,terminal:false});
  const line=await new Promise(resolve=>input.once('line',resolve));input.close();expect(line.length).toBeLessThanOrEqual(16384);
  const config=JSON.parse(line);expect(Object.keys(config).sort()).toEqual(['origin','username','password','election_id','receipts'].sort());
  expect(config.origin).toMatch(/^http:\/\/127\.0\.0\.1:[0-9]{1,5}$/);
  expect(config.election_id).toMatch(/^[0-9a-f-]{36}$/);expect(config.receipts).toHaveLength(2);
  browser=await chromium.launch({headless:true});const context=await browser.newContext();const page=await context.newPage();
  await context.addCookies([{name:'identity_canary',value:'synthetic-only',url:config.origin}]);
  let badWire=false,posts=0;
  page.on('request',request=>{
    const path=new URL(request.url()).pathname;
    if(!path.startsWith('/api/'))return;
    const headers=request.headers();
    badWire ||= 'cookie' in headers;
    if(path.startsWith('/api/v1/board'))badWire ||= 'authorization' in headers || config.receipts.some(hash=>request.url().includes(hash));
    else if(path.startsWith('/api/v1/publication/')){
      posts++;badWire ||= request.method()!=='POST' || request.postData()!=='{}' || !headers.authorization?.startsWith('Bearer adm1.');
    } else if(!path.startsWith('/api/v1/admin/'))badWire=true;
  });
  stage='login';await page.goto(config.origin+'/admin/publication');
  await page.getByLabel('Admin username').fill(config.username);await page.getByLabel('Admin password').fill(config.password);
  await page.getByRole('button',{name:'Sign in as administrator'}).click();
  stage='selection';await page.getByRole('button',{name:/· TALLIED$/}).click();
  await expect(page.getByRole('heading',{name:'Publish election results'})).toBeVisible();
  stage='confirmation';await page.getByRole('button',{name:'Publish results',exact:true}).click();expect(posts).toBe(0);
  await page.getByRole('button',{name:'Cancel publication'}).click();expect(posts).toBe(0);
  await page.getByRole('button',{name:'Publish results',exact:true}).click();
  const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/publication/elections/'+config.election_id+'/publish');
  stage='publication';await page.getByRole('button',{name:'Confirm publish'}).click();expect((await response).status()).toBe(200);
  await expect(page.getByText('PUBLISHED — publication is committed.')).toBeVisible();expect(posts).toBe(1);
  const link=await page.getByRole('link',{name:'Open public results and independent verification'}).getAttribute('href');
  expect(link).toBe('/public/results/'+config.election_id);
  await page.getByRole('button',{name:'Admin logout'}).click();await expect(page.getByRole('heading',{name:'Administrator sign-in'})).toBeVisible();
  stage='public_verification';await page.goto(config.origin+link);
  await expect(page.getByText('VERIFIED: Signed evidence chain verified.')).toBeVisible();
  await expect(page.getByText('Synthetic E2E candidate A: 1 (50.0%)',{exact:true})).toBeVisible();
  await expect(page.getByText('Synthetic E2E candidate B: 1 (50.0%)',{exact:true})).toBeVisible();
  for(const receipt of [...config.receipts,'0'.repeat(64)]){
    await page.goto(config.origin+'/public/verify');await page.getByLabel('Election ID').fill(config.election_id);
    await page.getByLabel('Receipt hash').fill(receipt);await page.getByRole('button',{name:'Verify receipt',exact:true}).click();
    await expect(page.getByText(receipt==='0'.repeat(64)?/NOT_FOUND:/:'VERIFIED: Signed evidence chain verified.')).toBeVisible();
  }
  expect(badWire).toBe(false);expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
  await context.close();await browser.close();browser=null;emit({event:'published_and_verified'});
} catch {process.exitCode=1;emit({event:'failure',stage});}
finally {if(browser)await browser.close().catch(()=>{});process.stdin.destroy();}

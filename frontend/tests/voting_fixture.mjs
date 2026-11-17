// Explicit synthetic browser fixture. No operator credentials, database or private-key files.
import { createServer as httpServer } from 'node:http';
import { createServer as viteServer } from 'vite';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { b64, canonical, fields, receipt, sha256, unb64, verifyProof, windowStatus } from '../src/voting/crypto.ts';

if (!process.argv.includes('--synthetic-voting-only')) throw new Error('Synthetic test opt-in required');
const suite=RSABSSA.SHA384.PSS.Randomized();
const ra=await suite.generateKey({modulusLength:3072,publicExponent:new Uint8Array([1,0,1])});
const tally=await crypto.subtle.generateKey({name:'RSA-OAEP',hash:'SHA-256',modulusLength:3072,publicExponent:new Uint8Array([1,0,1])},true,['encrypt','decrypt']);
const authority=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
async function key(publicKey,key_id) { const raw=new Uint8Array(await crypto.subtle.exportKey('spki',publicKey));return {key_id,spki:b64(raw),fingerprint:await sha256(raw)}; }
const iso=value=>new Date(Math.floor(value/1000)*1000).toISOString().replace('.000Z','Z');
const manifest={domain:'secure-evoting-election-manifest-v1',version:1,election_id:crypto.randomUUID(),opens_at:iso(Date.now()-3600000),closes_at:iso(Date.now()+3600000),candidates:[{candidate_id:crypto.randomUUID(),candidate_name:'Synthetic TEST candidate One'},{candidate_id:crypto.randomUUID(),candidate_name:'Synthetic TEST candidate Two'}].sort((a,b)=>a.candidate_id.localeCompare(b.candidate_id)),ra_key:await key(ra.publicKey,'browser-test-ra'),tally_key:await key(tally.publicKey,'browser-test-tally'),profile:'RSABSSA-SHA384-PSS-Randomized'};
const prefix=new TextEncoder().encode('EVOTE-MANIFEST-v1\0'), encoded=canonical(manifest), signed=new Uint8Array(prefix.length+encoded.length);signed.set(prefix);signed.set(encoded,prefix.length);
const bundle={manifest,signature:b64(new Uint8Array(await crypto.subtle.sign('Ed25519',authority.privateKey,signed)))};
const pin=b64(new Uint8Array(await crypto.subtle.exportKey('raw',authority.publicKey)));
const tokens=new Map(), reservations=new Map(), ballots=new Map();
const voters=new Map([['browser-test-voter-one',crypto.randomUUID()],['browser-test-voter-two',crypto.randomUUID()],['browser-test-voter-three',crypto.randomUUID()]]);
function reply(response,status,value) { response.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});response.end(value===undefined ? undefined : JSON.stringify(value)); }
const handler=async(request,response)=>{
  try {
    const path=new URL(request.url,'http://127.0.0.1').pathname;
    let raw='';for await(const chunk of request){raw+=chunk;if(raw.length>32768)throw new Error();}
    const body=raw ? JSON.parse(raw) : null;
    if(path==='/api/v1/ra/auth/login') {
      if(!voters.has(body?.username) || body?.password!=='Synthetic-Browser-Password')return reply(response,401,{});
      const token=b64(crypto.getRandomValues(new Uint8Array(32)));tokens.set(token,voters.get(body.username));return reply(response,200,{access_token:token,token_type:'Bearer'});
    }
    if(path.startsWith('/api/v1/ra/')) {
      const token=request.headers.authorization?.replace(/^Bearer /,'');if(!tokens.has(token))return reply(response,401,{});
      const voter=tokens.get(token);
      if(path.endsWith('/auth/me'))return reply(response,200,{voter_id:voter});
      if(path.endsWith('/auth/logout')){tokens.delete(token);return reply(response,204);}
      if(path==='/api/v1/ra/elections')return reply(response,200,{elections:[{election_id:manifest.election_id,bundle,eligibility:'checked_on_issue',credential_availability:'checked_on_issue'}]});
      if(path.endsWith('/credentials/issue')) {
        fields(body,['election_id','request_id','blinded_msg']);if(body.election_id!==manifest.election_id)throw new Error();
        const previous=reservations.get(voter);
        if(previous && (previous.request_id!==body.request_id || previous.blinded_msg!==body.blinded_msg))return reply(response,409,{});
        const blind=previous?.blind_sig ?? b64(await suite.blindSign(ra.privateKey,unb64(body.blinded_msg,384)));
        reservations.set(voter,{...body,blind_sig:blind});return reply(response,previous ? 200 : 201,{status:previous ? 'replayed' : 'issued',ra_key_id:manifest.ra_key.key_id,profile:manifest.profile,blind_sig:blind});
      }
    }
    if(path==='/api/v1/vote/ballots' || path==='/api/v1/vote/ballots/receipt') {
      if(request.headers.authorization || request.headers.cookie || request.headers['x-voter-id'])return reply(response,400,{});
      fields(body,['election_id','credential','envelope']);if(body.election_id!==manifest.election_id)return reply(response,422,{});
      await verifyProof(body.credential,body.envelope,bundle,pin);
      const digest=await receipt(body), serial=body.credential.message.serial, previous=ballots.get(serial);
      if(path.endsWith('/receipt'))return reply(response,previous===digest ? 200 : 404,previous===digest ? {status:'accepted',receipt_hash:digest} : {});
      if(previous || windowStatus(manifest)!=='open')return reply(response,409,{});
      ballots.set(serial,digest);return reply(response,201,{status:'accepted',receipt_hash:digest});
    }
    reply(response,404,{});
  } catch { reply(response,503,{detail:'Synthetic test service rejected request'}); }
};
const api=httpServer(handler), votingApi=httpServer(handler);
await new Promise(resolve=>api.listen(8003,'127.0.0.1',resolve));
await new Promise(resolve=>votingApi.listen(8004,'127.0.0.1',resolve));
process.env.RA_DEMO_TARGET='http://127.0.0.1:8003';process.env.VOTING_DEMO_TARGET='http://127.0.0.1:8004';process.env.VITE_ENABLE_VOTING='true';process.env.VITE_MANIFEST_AUTHORITY_PIN=pin;
const vite=await viteServer({configFile:'vite.config.ts',mode:'local-demo',server:{host:'127.0.0.1',port:5178,strictPort:true}});await vite.listen();
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>{void vite.close();api.close();votingApi.close();});

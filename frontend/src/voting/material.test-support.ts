// Generated TEST keys only; imported exclusively by tests, never by the UI.
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { b64, canonical, sha256, type Bundle, type PublicKeyInfo } from './crypto';

export async function testMaterial() {
  const ra=await RSABSSA.SHA384.PSS.Randomized().generateKey({modulusLength:3072,publicExponent:new Uint8Array([1,0,1])});
  const tally=await crypto.subtle.generateKey({name:'RSA-OAEP',hash:'SHA-256',modulusLength:3072,publicExponent:new Uint8Array([1,0,1])},true,['encrypt','decrypt']);
  const authority=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as CryptoKeyPair;
  async function key(publicKey:CryptoKey,key_id:string):Promise<PublicKeyInfo> { const raw=new Uint8Array(await crypto.subtle.exportKey('spki',publicKey));return {key_id,spki:b64(raw),fingerprint:await sha256(raw)}; }
  const now=Date.now(), iso=(value:number)=>new Date(Math.floor(value/1000)*1000).toISOString().replace('.000Z','Z');
  const manifest={domain:'secure-evoting-election-manifest-v1',version:1,election_id:crypto.randomUUID(),opens_at:iso(now-3600000),closes_at:iso(now+3600000),candidates:[{candidate_id:crypto.randomUUID(),candidate_name:'Synthetic TEST candidate'}],ra_key:await key(ra.publicKey,'test-ra'),tally_key:await key(tally.publicKey,'test-tally'),profile:'RSABSSA-SHA384-PSS-Randomized'};
  const prefix=new TextEncoder().encode('EVOTE-MANIFEST-v1\0'), data=canonical(manifest), signed=new Uint8Array(prefix.length+data.length);signed.set(prefix);signed.set(data,prefix.length);
  const bundle:Bundle={manifest,signature:b64(new Uint8Array(await crypto.subtle.sign('Ed25519',authority.privateKey,signed)))};
  return {ra,tally,authority,bundle,pin:b64(new Uint8Array(await crypto.subtle.exportKey('raw',authority.publicKey)))};
}

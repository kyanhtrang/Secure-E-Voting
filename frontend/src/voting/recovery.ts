import { b64, canonical, fields, messageBytes, receipt, requireValid, sha256, unb64, uuid, validateEnvelope, verifyManifest, verifyProof, type Bundle, type Envelope, type Pending, type Proof } from './crypto';

export interface PrivateState { version: number; bundle: Bundle; envelope: Envelope; pending: Pending; proof: Proof | null; phase: 'pending' | 'ready' | 'submission_unknown' | 'accepted'; receipt_hash: string | null }
export interface ProtectedState { version: number; context: { election_id: string; request_id: string; config_hash: string }; kdf: string; iterations: number; salt: string; nonce: string; ciphertext: string }
const ITERATIONS=600000;
function text(raw: Uint8Array) { return new TextDecoder('utf-8',{fatal:true}).decode(raw); }
function aad(context: ProtectedState['context']) { return canonical({domain:'EVOTE-BROWSER-RECOVERY-v1',...context}); }
async function derive(passphrase: string, salt: Uint8Array<ArrayBuffer>) {
  requireValid(passphrase.length >= 16 && passphrase.length <= 1024);
  const password=await crypto.subtle.importKey('raw',new TextEncoder().encode(passphrase),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',iterations:ITERATIONS,salt},password,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
export async function validateState(value: unknown, pin: string): Promise<PrivateState> {
  fields(value,['version','bundle','envelope','pending','proof','phase','receipt_hash']);
  requireValid(value.version === 1 && ['pending','ready','submission_unknown','accepted'].includes(String(value.phase)));
  const state=value as unknown as PrivateState;
  fields(state.pending,['version','request_id','message','prepared_msg','blinded_msg','inv','key_fingerprint']);
  requireValid(state.pending.version === 1); uuid(state.pending.request_id);
  const message=state.pending.message, encoded=messageBytes(message);
  await verifyManifest(state.bundle,pin,message.election_id); validateEnvelope(state.envelope,state.bundle.manifest);
  requireValid(message.config_hash === await sha256(canonical(state.bundle.manifest)) && message.envelope_hash === await sha256(canonical(state.envelope)) && message.key_id === state.bundle.manifest.ra_key.key_id && state.pending.key_fingerprint === state.bundle.manifest.ra_key.fingerprint);
  const prepared=unb64(state.pending.prepared_msg); requireValid(prepared.length === 32+encoded.length && b64(prepared.slice(32)) === b64(encoded));
  unb64(state.pending.blinded_msg,384); unb64(state.pending.inv,384);
  if (state.proof !== null) {
    await verifyProof(state.proof,state.envelope,state.bundle,pin);
    requireValid(b64(messageBytes(state.proof.message)) === b64(encoded) && state.proof.prepared_msg === state.pending.prepared_msg);
  }
  requireValid(state.phase === 'pending' || state.proof !== null);
  requireValid(state.phase === 'accepted' ? state.proof !== null && state.receipt_hash === await receipt({election_id:message.election_id,credential:state.proof,envelope:state.envelope}) : state.receipt_hash === null);
  return state;
}
export async function protect(state: PrivateState, passphrase: string, pin: string): Promise<ProtectedState> {
  await validateState(state,pin);
  const context={election_id:state.pending.message.election_id,request_id:state.pending.request_id,config_hash:state.pending.message.config_hash};
  const salt=crypto.getRandomValues(new Uint8Array(16)), nonce=crypto.getRandomValues(new Uint8Array(12));
  const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad(context),tagLength:128},await derive(passphrase,salt),canonical(state));
  requireValid(encrypted.byteLength <= 262144);
  return {version:1,context,kdf:'PBKDF2-SHA256',iterations:ITERATIONS,salt:b64(salt),nonce:b64(nonce),ciphertext:b64(new Uint8Array(encrypted))};
}
export async function unlock(blob: unknown, passphrase: string, pin: string): Promise<PrivateState> {
  fields(blob,['version','context','kdf','iterations','salt','nonce','ciphertext']);
  requireValid(blob.version === 1 && blob.kdf === 'PBKDF2-SHA256' && blob.iterations === ITERATIONS);
  fields(blob.context,['election_id','request_id','config_hash']); uuid(blob.context.election_id); uuid(blob.context.request_id);
  const encrypted=blob as unknown as ProtectedState;
  const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(blob.nonce,12),additionalData:aad(encrypted.context),tagLength:128},await derive(passphrase,unb64(blob.salt,16)),unb64(blob.ciphertext,undefined,524288));
  const raw=new Uint8Array(plain), parsed: unknown=JSON.parse(text(raw)); requireValid(b64(canonical(parsed)) === b64(raw));
  const state=await validateState(parsed,pin);
  requireValid(state.pending.request_id === encrypted.context.request_id && state.pending.message.election_id === encrypted.context.election_id && state.pending.message.config_hash === encrypted.context.config_hash);
  return state;
}
export function protectedFile(blob: ProtectedState): string { return text(canonical(blob)); }
export function parseProtectedFile(contents: string): unknown { requireValid(contents.length <= 524288); const parsed: unknown=JSON.parse(contents); requireValid(text(canonical(parsed)) === contents); return parsed; }

export interface RecoveryStore { list(): Promise<ProtectedState[]>; save(blob: ProtectedState, create: boolean): Promise<void> }
export function browserRecoveryStore(): RecoveryStore {
  function open(): Promise<IDBDatabase> { return new Promise((resolve,reject) => { const request=indexedDB.open('secure-evoting-voter-recovery-v1',1); request.onupgradeneeded=() => request.result.createObjectStore('pending'); request.onsuccess=() => resolve(request.result); request.onerror=() => reject(new Error('Protected recovery storage unavailable')); }); }
  return {
    async list() { const db=await open(); try { return await new Promise<ProtectedState[]>((resolve,reject) => { const tx=db.transaction('pending','readonly'), request=tx.objectStore('pending').getAll(); tx.oncomplete=() => resolve(request.result as ProtectedState[]); tx.onerror=() => reject(new Error('Protected recovery storage unavailable')); }); } finally { db.close(); } },
    async save(blob,create) {
      const db=await open();
      try {
        await new Promise<void>((resolve,reject)=>{
          const tx=db.transaction('pending','readwrite'), store=tx.objectStore('pending');
          if (create) store.add(blob,blob.context.election_id);
          else {
            const read=store.get(blob.context.election_id);
            read.onsuccess=()=>{
              const previous=read.result as ProtectedState | undefined;
              if (previous && (previous.context?.request_id !== blob.context.request_id || previous.context?.config_hash !== blob.context.config_hash)) { tx.abort(); return; }
              store.put(blob,blob.context.election_id);
            };
          }
          tx.oncomplete=()=>resolve();
          tx.onerror=()=>reject(new Error('Existing or unavailable protected recovery state'));
          tx.onabort=()=>reject(new Error('Protected recovery transaction failed'));
        });
      } finally { db.close(); }
    },
  };
}

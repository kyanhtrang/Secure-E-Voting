import { canonical,uuid } from '../voting/crypto';

export class BoardFailure extends Error {
  readonly status:number;
  constructor(status=503){super('Public evidence is unavailable.');this.status=status;}
}
export async function boardGet(path:string):Promise<unknown> {
  if(!/^\/api\/v1\/board(?:\/[a-z0-9/-]+)?(?:\?cursor=[0-9a-f-]+)?$/.test(path))throw new BoardFailure(422);
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),30000);
  try {
    const response=await fetch(path,{method:'GET',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',signal:controller.signal,headers:{Accept:'application/json'}});
    if(!response.ok)throw new BoardFailure([404,422,503].includes(response.status)?response.status:503);
    if(!response.body || response.headers.get('Cache-Control')!=='no-store' || !response.headers.get('Content-Type')?.startsWith('application/json'))throw new BoardFailure();
    const reader=response.body.getReader(),parts:Uint8Array[]=[];let size=0;
    try { while(true){const next=await reader.read();if(next.done)break;size+=next.value.length;if(size>16777216)throw new BoardFailure();parts.push(next.value);} }
    finally { await reader.cancel(); }
    const raw=new Uint8Array(size);let offset=0;for(const part of parts){raw.set(part,offset);offset+=part.length;}
    const text=new TextDecoder('utf-8',{fatal:true}).decode(raw),value:unknown=JSON.parse(text);
    if(new TextDecoder().decode(canonical(value))!==text)throw new BoardFailure(422);
    return value;
  } catch(error) { if(error instanceof BoardFailure)throw error;throw new BoardFailure(); }
  finally { clearTimeout(timer); }
}
export function evidence(election:string):Promise<unknown> {uuid(election);return boardGet('/api/v1/board/'+election+'/evidence');}

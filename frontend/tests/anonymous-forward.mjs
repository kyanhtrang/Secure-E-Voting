// Test transport only. Never forward anonymous voting via the RA/browser cookie jar.
import { request } from '@playwright/test';

export async function withAnonymousForward(route, inspect) {
  const original=route.request(), url=new URL(original.url());
  const headers=await original.allHeaders();
  const forbidden=['authorization','cookie','proxy-authorization','x-voter-id','x-ra-token','x-username','x-request-id'];
  if(url.protocol!=='http:' || url.hostname!=='127.0.0.1' || url.username || url.password
    || url.pathname!=='/api/v1/vote/ballots' || url.search || original.method()!=='POST'
    || forbidden.some(name=>name in headers))throw new Error('Anonymous loopback request required');
  // A new isolated jar cannot inherit the canary cookie or RA request defaults.
  const isolated=await request.newContext({storageState:{cookies:[],origins:[]}});
  try {
    const response=await isolated.fetch(original,{maxRedirects:0,maxRetries:0,failOnStatusCode:false,timeout:15000});
    return await inspect(response); // Read the response while its context is alive.
  } finally { await isolated.dispose(); }
}

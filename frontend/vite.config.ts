import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export function localTarget(value = 'http://127.0.0.1:8000'): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('The RA demo target must be a loopback HTTP origin.'); }
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(url.hostname)
    || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('The RA demo target must be a loopback HTTP origin.');
  }
  return url.origin;
}

export function separateVotingTarget(ra: string, value='http://127.0.0.1:8001'): string {
  const target=localTarget(value);
  if ((new URL(ra).port || '80') === (new URL(target).port || '80')) throw new Error('RA and Voting require separate loopback ports.');
  return target;
}

export default defineConfig(({ mode }) => {
  const enabled = mode === 'local-demo';
  const raTarget=localTarget(process.env.RA_DEMO_TARGET);
  const votingTarget=process.env.VITE_ENABLE_VOTING === 'true' ? separateVotingTarget(raTarget,process.env.VOTING_DEMO_TARGET) : localTarget(process.env.VOTING_DEMO_TARGET ?? 'http://127.0.0.1:8001');
  const adminTarget=localTarget(process.env.ADMIN_DEMO_TARGET ?? 'http://127.0.0.1:8002');
  if (enabled && process.env.VITE_ENABLE_ADMIN === 'true' && [new URL(raTarget).port,new URL(votingTarget).port].includes(new URL(adminTarget).port)) throw new Error('Admin requires a separate loopback port.');
  const tallyTarget=localTarget(process.env.TALLY_DEMO_TARGET ?? 'http://127.0.0.1:8005');
  if (enabled && process.env.VITE_ENABLE_TALLY === 'true' && [raTarget,votingTarget,adminTarget].some(value => new URL(value).port === new URL(tallyTarget).port)) throw new Error('Tally requires a separate loopback port.');
  const boardTarget=localTarget(process.env.BOARD_DEMO_TARGET ?? 'http://127.0.0.1:8006');
  if(enabled && process.env.VITE_ENABLE_BOARD==='true' && [raTarget,votingTarget,adminTarget,tallyTarget].some(value=>new URL(value).port===new URL(boardTarget).port))throw new Error('Board requires a separate loopback port.');
  const headers = { 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store' };
  // Preserve Host AND Origin. The existing backend checks that they agree;
  // changeOrigin/Origin stripping would bypass that check or break local access.
  const proxy = enabled ? {
    ...(process.env.VITE_ENABLE_BOARD==='true'?{'^/api/v1/board':{target:boardTarget,changeOrigin:false,xfwd:false,followRedirects:false,
      configure(proxy:Parameters<NonNullable<import('vite').ProxyOptions['configure']>>[0]){
        proxy.on('proxyReq',(outgoing,incoming)=>{if(['authorization','cookie','proxy-authorization','x-voter-id','x-ra-token','x-request-id','x-username','x-admin-token','x-admin-id','x-tally-token'].some(name=>incoming.headers[name]))outgoing.destroy(new Error('Anonymous Board request required'));});
      }}}:{}),
    ...(process.env.VITE_ENABLE_TALLY === 'true' ? { '^/api/v1/tally/': { target:tallyTarget, changeOrigin:false, xfwd:false, followRedirects:false } } : {}),
    ...(process.env.VITE_ENABLE_ADMIN === 'true' ? { '^/api/v1/admin/': { target:adminTarget, changeOrigin:false, xfwd:false, followRedirects:false } } : {}),
    '^/api/v1/ra/auth/(login|me|logout)$': {
      target: localTarget(process.env.RA_DEMO_TARGET), changeOrigin: false,
      xfwd: false, followRedirects: false,
    },
    '^/api/v1/ra/(elections|credentials/issue)$': {
      target: localTarget(process.env.RA_DEMO_TARGET), changeOrigin:false, xfwd:false, followRedirects:false,
    },
    '^/api/v1/vote/ballots(/receipt)?$': {
      target: votingTarget,
      changeOrigin:false, xfwd:false, followRedirects:false,
      configure(proxy: Parameters<NonNullable<import('vite').ProxyOptions['configure']>>[0]) {
        // Do not silently strip a leaked identity header: reject the request.
        proxy.on('proxyReq',(outgoing,incoming) => {
          if (incoming.headers.authorization || incoming.headers.cookie || incoming.headers['proxy-authorization'] || incoming.headers['x-voter-id'] || incoming.headers['x-ra-token'] || incoming.headers['x-username'] || incoming.headers['x-request-id']) outgoing.destroy(new Error('Anonymous request required'));
        });
      },
    },
  } : undefined;
  return {
    plugins: [react()],
    define: { __LOCAL_RA_DEMO__: JSON.stringify(enabled) },
    server: { host: '127.0.0.1', port: 5173, strictPort: true, cors: false, headers,
      allowedHosts: ['127.0.0.1', 'localhost'], ...(proxy ? { proxy } : {}) },
    preview: { host: '127.0.0.1', port: 4173, strictPort: true, cors: false, headers,
      allowedHosts: ['127.0.0.1', 'localhost'], ...(proxy ? { proxy } : {}) },
    build: { sourcemap: false },
  };
});

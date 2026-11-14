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

export default defineConfig(({ mode }) => {
  const enabled = mode === 'local-demo';
  const headers = { 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store' };
  // Preserve Host AND Origin. The existing backend checks that they agree;
  // changeOrigin/Origin stripping would bypass that check or break local access.
  const proxy = enabled ? {
    '^/api/v1/ra/auth/(login|me|logout)$': {
      target: localTarget(process.env.RA_DEMO_TARGET), changeOrigin: false,
      xfwd: false, followRedirects: false,
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

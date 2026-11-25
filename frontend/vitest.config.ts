import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  define: { __LOCAL_RA_DEMO__: 'false', __LOCAL_PUBLICATION_PROXY__: 'false' },
  // Bound CPU contention between real RSA fixture suites; keep existing timeouts.
  test: { maxWorkers: 2, environment: 'jsdom', setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    environmentOptions: { jsdom: { url: 'http://127.0.0.1:5173' } } },
});

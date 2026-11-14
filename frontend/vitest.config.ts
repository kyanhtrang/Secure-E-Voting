import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  define: { __LOCAL_RA_DEMO__: 'false' },
  test: { environment: 'jsdom', setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    environmentOptions: { jsdom: { url: 'http://127.0.0.1:5173' } } },
});

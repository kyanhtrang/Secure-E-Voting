import { defineConfig, devices } from '@playwright/test';
export default defineConfig({
  testDir: './tests/admin-browser', workers: 1, fullyParallel: false, retries: 0, reporter: 'list',
  use: { baseURL: 'http://127.0.0.1:5177', ...devices['Desktop Chrome'],
    ...(process.platform === 'win32' ? { channel: 'msedge' } : {}), screenshot: 'off', trace: 'off', video: 'off' },
  webServer: { command: 'npm run dev:local -- --port 5177', env: { VITE_ENABLE_ADMIN: 'true', VITE_ENABLE_PUBLICATION:'true', PUBLICATION_DEMO_TARGET:'http://127.0.0.1:8007' },
    url: 'http://127.0.0.1:5177', reuseExistingServer: false, stdout: 'ignore', stderr: 'pipe' },
});

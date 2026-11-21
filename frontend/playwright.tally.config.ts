import { defineConfig, devices } from '@playwright/test';
export default defineConfig({
  testDir: './tests/tally-browser', workers: 1, retries: 0, reporter: 'list',
  use: { baseURL: 'http://127.0.0.1:5189', ...devices['Desktop Chrome'],
    ...(process.platform === 'win32' ? { channel: 'msedge' } : {}), trace: 'off', video: 'off', screenshot: 'off' },
  webServer: { command: 'npm run dev:local -- --port 5189', env: { VITE_ENABLE_TALLY: 'true' },
    url: 'http://127.0.0.1:5189', reuseExistingServer: false, stdout: 'ignore', stderr: 'pipe' },
});

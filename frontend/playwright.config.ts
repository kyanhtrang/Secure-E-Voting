import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const directory = dirname(fileURLToPath(import.meta.url));
const python = process.env.EVOTE_TEST_PYTHON ?? 'python';
export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'list',
  use: { baseURL: 'http://127.0.0.1:5174', ...devices['Desktop Chrome'],
    ...(process.platform === 'win32' ? { channel: 'msedge' } : {}),
    screenshot: 'off', trace: 'off', video: 'off' }, // No credential-bearing traces/artifacts.
  webServer: [
    { command: `"${python}" tests/auth_fixture.py --synthetic-auth-only`, cwd: directory,
      url: 'http://127.0.0.1:8001/openapi.json', reuseExistingServer: false, timeout: 20_000, stdout: 'ignore', stderr: 'pipe' },
    { command: 'npm run dev:local -- --port 5174', cwd: directory,
      env: { RA_DEMO_TARGET: 'http://127.0.0.1:8001' },
      url: 'http://127.0.0.1:5174', reuseExistingServer: false, timeout: 20_000, stdout: 'ignore', stderr: 'pipe' },
    { command: 'npm run preview -- --port 5176', cwd: directory,
      url: 'http://127.0.0.1:5176', reuseExistingServer: false, timeout: 20_000, stdout: 'ignore', stderr: 'pipe' },
  ],
});

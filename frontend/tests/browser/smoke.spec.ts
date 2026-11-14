import { test, expect } from '@playwright/test';

async function login(page: import('@playwright/test').Page) {
  await page.goto('/voter/login');
  await page.getByLabel('Username', { exact: true }).fill('demo-voter');
  await page.getByLabel('Password', { exact: true }).fill('synthetic-demo-password');
  await page.getByRole('button', { name: 'Sign in securely' }).click();
  await expect(page.getByRole('heading', { name: 'Ready when your election is.' })).toBeVisible();
}
test('real RA HTTP login/me/logout through unchanged-origin Vite proxy', async ({ page }) => {
  const requests: string[] = [];
  page.on('request', request => { const path = new URL(request.url()).pathname; if (path.startsWith('/api/')) requests.push(path); });
  await login(page);
  expect(requests.slice(0, 2)).toEqual(['/api/v1/ra/auth/login', '/api/v1/ra/auth/me']);
  const storage = await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }));
  expect(storage).toEqual({ local: 0, session: 0 });
  await page.getByRole('button', { name: 'Check session' }).click();
  await expect(page.getByText('Session verified', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByText('You have signed out.')).toBeVisible();
  expect(requests).toContain('/api/v1/ra/auth/logout');
});
test('incorrect password and protected route, no secret in feedback', async ({ page }) => {
  await page.goto('/voter/elections');
  await expect(page).toHaveURL(/\/voter\/login$/);
  await page.getByLabel('Username', { exact: true }).fill('demo-voter');
  await page.getByLabel('Password', { exact: true }).fill('synthetic-incorrect-password');
  await page.getByRole('button', { name: 'Sign in securely' }).click();
  await expect(page.getByText('The username or password is incorrect.')).toBeVisible();
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
});
test('expired session returns to login and reload forgets the session', async ({ page }) => {
  await login(page);
  await page.route('**/api/v1/ra/auth/me', route => route.fulfill({ status: 401, contentType: 'application/json', body: '{"detail":"Invalid authentication credentials"}' }));
  await page.getByRole('button', { name: 'Check session' }).click();
  await expect(page.getByText('Your session has ended. Please sign in again.')).toBeVisible();
  await page.unroute('**/api/v1/ra/auth/me');
  await login(page);
  await page.reload();
  await expect(page).toHaveURL(/\/voter\/login$/);
});
test('public and anonymous routes send no RA requests; publication cannot come from a URL', async ({ page }) => {
  const authCalls: string[] = [];
  page.on('request', request => { if (request.url().includes('/api/v1/ra/')) authCalls.push(request.method()); });
  await page.goto('/public/results/unknown?status=PUBLISHED&counted=900');
  await expect(page.getByText('No published chart data')).toBeVisible();
  await expect(page.getByLabel('Not published', { exact: true })).toHaveCount(4);
  await page.goto('/public/verify');
  await expect(page.getByRole('button', { name: 'Verify receipt', exact: true })).toBeDisabled();
  await page.goto('/vote');
  await expect(page.getByRole('button', { name: 'Submit ballot' })).toBeDisabled();
  expect(authCalls).toEqual([]);
});
test('desktop and mobile layouts fit and keyboard navigation remains available', async ({ page }) => {
  for (const size of [{ width: 1440, height: 1000 }, { width: 390, height: 844 }, { width: 320, height: 740 }]) {
    await page.setViewportSize(size);
    for (const route of ['/voter/login', '/admin/status', '/public/results/unavailable']) {
      await page.goto(route);
      await expect(page.locator('main h1')).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    }
    await page.goto('/public');
    await expect(page.getByRole('heading', { name: 'Election outcomes, open to everyone.' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    if (size.width < 700) {
      await page.getByRole('button', { name: 'Open navigation' }).focus();
      await page.keyboard.press('Enter');
      await expect(page.getByRole('link', { name: 'Verify a receipt', exact: true })).toBeVisible();
      await expect(page.getByRole('link', { name: 'Published elections', exact: true })).toBeFocused();
      await page.keyboard.press('Tab');
      await expect(page.getByRole('link', { name: 'Bulletin board', exact: true })).toBeFocused();
      await page.keyboard.press('Tab');
      await expect(page.getByRole('link', { name: 'Verify a receipt', exact: true })).toBeFocused();
      await page.keyboard.press('Enter');
      await expect(page.getByRole('heading', { name: 'Every receipt needs real evidence.' })).toBeVisible();
    }
  }
});
test('proxy preserves origin checks and admin actions stay unavailable', async ({ page, request }) => {
  const rejected = await request.post('/api/v1/ra/auth/login', {
    headers: { Origin: 'https://untrusted.invalid' },
    data: { username: 'demo-voter', password: 'synthetic-demo-password' },
  });
  expect(rejected.status()).toBe(403);
  const calls: string[] = [];
  page.on('request', value => { if (new URL(value.url()).pathname.startsWith('/api/')) calls.push(value.method()); });
  await page.goto('/admin/status');
  await expect(page.getByText('Read-only foundation.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Open election' }).first()).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Close election' })).toBeDisabled();
  expect(calls).toEqual([]);
});
test('built default preview keeps authentication disabled without any API request', async ({ page }) => {
  const calls: string[] = [];
  page.on('request', value => { if (new URL(value.url()).pathname.startsWith('/api/')) calls.push(value.method()); });
  const response = await page.goto('http://127.0.0.1:5176/voter/login');
  expect(response?.headers()['x-frame-options']).toBe('DENY');
  expect(response?.headers()['cache-control']).toBe('no-store');
  await expect(page.getByRole('heading', { name: 'A trusted place for your voice.' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in securely' })).toBeDisabled();
  await expect(page.getByLabel('Password', { exact: true })).toBeDisabled();
  expect(calls).toEqual([]);
});

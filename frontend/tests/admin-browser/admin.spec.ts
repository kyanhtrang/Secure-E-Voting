// Synthetic transport UI checks. Real PostgreSQL contracts run in a separate gate.
import { expect, test } from '@playwright/test';

for (const width of [390, 1440]) {
  test(`administrator authorization and draft creation at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    let logged = false;
    const elections: Record<string, unknown>[] = [];
    await page.route('**/api/v1/admin/**', async route => {
      const request = route.request(); const url = new URL(request.url()); const path = url.pathname;
      expect(request.headers()['cookie']).toBeUndefined();
      if (path.endsWith('/auth/login')) {
        expect(request.headers()['authorization']).toBeUndefined(); logged = true;
        return route.fulfill({ json: { access_token: 'adm1.' + 'A'.repeat(43), token_type: 'bearer' } });
      }
      expect(logged).toBe(true);
      expect(request.headers()['authorization']).toBe('Bearer adm1.' + 'A'.repeat(43));
      if (path.endsWith('/auth/me')) return route.fulfill({ json: { admin_id: '11111111-1111-4111-8111-111111111111', role: 'ELECTION_ADMIN' } });
      if (path.endsWith('/auth/logout')) { logged = false; return route.fulfill({ status: 204 }); }
      if (path.endsWith('/keysets')) return route.fulfill({ json: { keysets: [] } });
      if (path.endsWith('/audit')) return route.fulfill({ json: { events: [] } });
      if (path.endsWith('/elections') && request.method() === 'POST') {
        const draft = { ...request.postDataJSON(), election_id: '22222222-2222-4222-8222-222222222222', revision: 1, phase: 'DRAFT', status: 'DRAFT', ra_ready: false, candidates: [], config_hash: null, keyset_id: null, bundle: null };
        elections.push(draft); return route.fulfill({ status: 201, json: draft });
      }
      if (path.endsWith('/elections')) return route.fulfill({ json: { elections } });
      return route.fulfill({ json: elections[0] });
    });
    await page.goto('/admin');
    await expect(page.getByRole('heading', { name: 'Administrator sign-in' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create draft', exact: true })).toHaveCount(0);
    await page.getByLabel('Admin username').fill('synthetic-admin');
    await page.getByLabel('Admin password').fill('synthetic-test-only');
    await page.getByRole('button', { name: 'Sign in as administrator' }).click();
    await expect(page.getByText('No managed elections')).toBeVisible();
    await page.getByLabel('Election title').fill('Synthetic browser election');
    await page.getByLabel('Opens at (UTC)').fill('2026-01-01T00:00:00');
    await page.getByLabel('Closes at (UTC)').fill('2027-01-01T00:00:00');
    await page.getByRole('button', { name: 'Create draft', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Synthetic browser election' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Open / reconcile opening' })).toBeDisabled();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const menu = page.getByRole('button', { name: 'Open navigation' });
    if (await menu.isVisible()) await menu.click();
    await page.getByRole('link', { name: 'Election status', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Synthetic browser election' })).toBeVisible();
    await page.getByRole('button', { name: 'Admin logout' }).click();
    await expect(page.getByRole('heading', { name: 'Administrator sign-in' })).toBeVisible();
  });
}

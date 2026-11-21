// Synthetic UI fixture only. Real PostgreSQL/decryption runs in the separate gate.
import { expect, test } from '@playwright/test';
for (const width of [390, 1440]) {
  test(`operator confirmation and aggregate-only output at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 950 });
    let status = 'CLOSED', runs = 0;
    const election = '11111111-1111-4111-8111-111111111111';
    await page.route('**/api/v1/tally/**', async route => {
      const path = new URL(route.request().url()).pathname;
      expect(route.request().headers()['cookie']).toBeUndefined();
      if (path.endsWith('/auth/login')) return route.fulfill({ json: { access_token: 'tly1.' + 'A'.repeat(43), token_type: 'bearer' } });
      expect(route.request().headers()['authorization']).toBe('Bearer tly1.' + 'A'.repeat(43));
      if (path.endsWith('/auth/me')) return route.fulfill({ json: { role: 'TALLY_OPERATOR' } });
      if (path.endsWith('/auth/logout')) return route.fulfill({ status: 204 });
      if (path.endsWith('/elections')) return route.fulfill({ json: { elections: [{ election_id: election, title: 'Synthetic closed election', status, ra_ready: true }] } });
      if (path.endsWith('/run')) { expect(route.request().postDataJSON()).toEqual({}); status = 'TALLIED'; runs++; }
      return route.fulfill({ json: { report: { election_id: election, snapshot_digest: 'a'.repeat(64), accepted_total: 3, valid_total: 2, counted_total: 2, invalid_total: 1,
        candidate_counts: [{ candidate_id: election, vote_count: 2 }], invalid_reasons: { KEY_WRAP: 0, AEAD: 1, PLAINTEXT: 0 } }, report_digest: 'b'.repeat(64), signature: 'synthetic-test-only', signing_key_id: 'synthetic-key', candidates: [{ candidate_id: election, candidate_name: 'Synthetic candidate' }] } });
    });
    await page.goto('/admin/tally');
    await page.getByLabel('Tally username').fill('synthetic');
    await page.getByLabel('Tally password').fill('synthetic-test-only');
    await page.getByRole('button', { name: 'Sign in to Tally' }).click();
    await page.getByRole('combobox', { name: 'Election', exact: true }).selectOption(election);
    const run = page.getByRole('button', { name: 'Verify and tally', exact: true });
    await expect(run).toBeDisabled();
    await page.getByRole('checkbox').check();
    await run.click();
    await expect(page.getByRole('heading', { name: 'Restricted aggregate report' })).toBeVisible();
    expect(runs).toBe(1);
    await expect(run).toBeDisabled();
    await expect(page.getByText('Synthetic candidate', { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole('button', { name: 'Tally logout' }).click();
    await expect(page.getByRole('button', { name: 'Sign in to Tally' })).toBeVisible();
  });
}

import { test, expect } from '@playwright/test';

test('late NVD settings cannot replace the selected CVE settings', async ({ page }) => {
  let releaseNvd!: () => void;
  let nvdStarted!: () => void;
  const blocked = new Promise<void>(resolve => { releaseNvd = resolve; });
  const started = new Promise<void>(resolve => { nvdStarted = resolve; });
  const saved: unknown[] = [];
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/admin/events')) return route.abort();
    let body: unknown = {};
    if (path.endsWith('/auth/me')) body = { username: 'admin', role: 'admin', csrf: 'test' };
    if (path.endsWith('/projects')) body = [];
    if (path.endsWith('/admin/status')) body = { workers: [], sources: [], schedules: [], queue: [], jobs: [] };
    if (path.includes('/schedules/')) body = { enabled: false, mode: 'cron', expression: '0 7 * * *', timezone: 'UTC', interval_seconds: 1800, upcoming: [] };
    if (path.endsWith('/settings/nvd')) {
      nvdStarted();
      await blocked;
      body = { version: 1, settings: { request_timeout: '99s' }, has_api_key: false };
    }
    if (path.endsWith('/settings/cve')) {
      if (route.request().method() === 'PUT') saved.push(route.request().postDataJSON());
      body = { version: 2, settings: { request_timeout: '42s' }, has_api_key: false };
    }
    await route.fulfill({ json: body }).catch(() => {}); // Aborted old request is expected.
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await started;
  await page.getByRole('button', { name: 'CVE synchronization', exact: true }).click();
  await expect(page.getByLabel('request timeout')).toHaveValue('42s');
  releaseNvd();
  await page.getByRole('button', { name: 'Save worker settings' }).click();
  await expect(page.getByText('Worker settings saved', { exact: true })).toBeVisible();
  expect(saved).toEqual([{ request_timeout: '42s' }]);
  await expect(page.getByLabel('request timeout')).toHaveValue('42s');
});

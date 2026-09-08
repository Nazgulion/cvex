import { test, expect, type Page } from '@playwright/test';

const project = { id: 'project-1', company: 'Orion Systems', name: 'Gateway firmware', active_version_id: 'v1', schedule_enabled: true, next_run: '2026-09-09T05:00:00Z', filename: 'gateway-firmware.spdx.json', active_version: '2.4.0', latest_state: 'succeeded' };
const detail = { ...project, versions: [{ id: 'v1', label: '2.4.0', filename: project.filename, created_at: '2026-09-08T08:00:00Z' }], jobs: [] };

async function mockWorkspace(page: Page, slow = false) {
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/admin/events')) return route.abort();
    let body: unknown = {};
    if (path.endsWith('/auth/me')) body = { username: 'design-review', role: 'admin', csrf: 'test' };
    if (path.endsWith('/projects')) body = [project];
    if (path.endsWith('/projects/project-1')) {
      if (slow) await new Promise(resolve => setTimeout(resolve, 6200));
      body = detail;
    }
    if (path.endsWith('/admin/status')) body = { database_bytes: 4500000000, disk_free_bytes: 100000000000, disk_total_bytes: 200000000000, workers: [], sources: [], schedules: [], queue: [], jobs: [], recent_syncs: [{ id: 'run-1', source: 'nvd', status: 'succeeded', started_at: '2026-09-08T08:00:00Z', finished_at: '2026-09-08T08:00:12Z', duration_seconds: 12, processed: '180', changed: '34' }], server_time: new Date().toISOString() };
    await route.fulfill({ json: body }).catch(() => {});
  });
}

test('project clarity, keyboard modal, responsive themes and no idle dashboard requests', async ({ page }) => {
  const errors: string[] = [];
  const metricsRequests: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { if (request.url().includes('/admin/')) metricsRequests.push(request.url()); });
  await mockWorkspace(page);
  await page.goto('/');
  await expect(page.getByRole('button', { name: /Orion Systems/ })).toBeVisible();
  await page.screenshot({ path: 'test-results/overview-polished.png', fullPage: true });
  expect(metricsRequests).toEqual([]);
  await page.getByRole('button', { name: 'New project', exact: true }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByLabel('Company', { exact: true })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'New project', exact: true })).toBeFocused();
  await page.getByLabel('Search projects').fill('no-such-project');
  await expect(page.getByText('No matching projects')).toBeVisible();
  await page.getByLabel('Search projects').fill('');
  await page.getByRole('button', { name: /Orion Systems/ }).click();
  const selected = page.getByRole('region', { name: 'Selected SBOM for scanning' });
  await expect(selected).toContainText(project.filename);
  await expect(selected).toContainText('2.4.0');
  await page.screenshot({ path: 'test-results/project-polished.png', fullPage: true });
  await page.getByRole('button', { name: 'Light appearance' }).click();
  await page.screenshot({ path: 'test-results/project-light.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Change password', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: 'test-results/project-mobile.png', fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('button', { name: 'Architecture', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Source synchronization history' })).toContainText('12.0s');
  await page.screenshot({ path: 'test-results/architecture-polished.png', fullPage: true });
  expect(errors).toEqual([]);
});

test('a project request slower than the polling interval can finish', async ({ page }) => {
  await mockWorkspace(page, true);
  await page.goto('/');
  await page.getByRole('button', { name: /Orion Systems/ }).click();
  await expect(page.getByRole('heading', { name: 'Orion Systems — Gateway firmware' })).toBeVisible({ timeout: 12000 });
});

test('an expired session returns to sign in without stale project data', async ({ page }) => {
  await mockWorkspace(page);
  await page.goto('/');
  await page.getByRole('button', { name: /Orion Systems/ }).click();
  await expect(page.getByRole('heading', { name: 'Orion Systems — Gateway firmware' })).toBeVisible();
  await page.route('**/api/v1/projects/project-1/runs', route => route.fulfill({ status: 401, json: { detail: 'Please sign in' } }));
  await page.getByRole('button', { name: 'Run now', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Sign in to CVEX' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Orion Systems — Gateway firmware' })).toHaveCount(0);
});

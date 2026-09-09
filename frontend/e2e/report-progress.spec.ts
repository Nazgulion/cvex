import { test, expect, type Page } from '@playwright/test';

const project = { id: 'progress-project', company: 'Orion', name: 'Gateway', active_version_id: 'v1', versions: [], jobs: [] };
const job = (id: string, state: string, severity: Record<string, number> | null = null) => ({
  id, state, created_at: `2026-09-${id.padStart(2, '0')}T08:00:00Z`, started_at: null, finished_at: null,
  scheduled_at: null, trigger: 'manual', version_label: '1.0', progress: 0, total: null, error: null,
  summary: severity === null ? null : { counts: { severity } },
});

async function openProject(page: Page, jobs: () => unknown[]) {
  await page.route('**/api/v1/**', route => {
    const path = new URL(route.request().url()).pathname;
    const body = path.endsWith('/auth/me') ? { username: 'test', role: 'admin', csrf: 'test' }
      : path.endsWith('/projects') ? [project] : { ...project, jobs: jobs() };
    return route.fulfill({ json: body });
  });
  await page.goto('/');
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'Gateway', exact: true }) }).click();
  await expect(page.getByRole('heading', { name: 'Orion — Gateway' })).toBeVisible();
}

test('live progress updates from queued through scanning and export', async ({ page }) => {
  test.setTimeout(45000);
  let current = { ...job('1', 'queued'), progress: 99, total: 100 };
  await openProject(page, () => [current]);
  const progress = page.getByRole('progressbar', { name: 'Component scan progress' });
  await expect(progress).toHaveAttribute('aria-valuenow', '0');
  await expect(page.getByText('Waiting to start', { exact: true })).toBeVisible();
  current = { ...current, state: 'scanning', progress: 37 };
  await expect(progress).toHaveAttribute('aria-valuenow', '37', { timeout: 8000 });
  await expect(page.getByText('37%', { exact: true })).toBeVisible();
  await page.screenshot({ path: 'test-results/scan-progress.png', fullPage: true });
  current = { ...current, state: 'exporting', progress: 100 };
  await expect(progress).toHaveAttribute('aria-valuenow', '100', { timeout: 8000 });
  await expect(page.getByText('Scan complete · writing reports', { exact: true })).toBeVisible();
  current = { ...current, state: 'succeeded' };
  await expect(progress).toHaveCount(0, { timeout: 8000 });
});

test('preparing and bounded percentages never show NaN or exceed 100', async ({ page }) => {
  await openProject(page, () => [job('1', 'scanning'), { ...job('2', 'scanning'), progress: 999, total: 3 }]);
  const bars = page.getByRole('progressbar');
  await expect(bars.nth(0)).toHaveAttribute('aria-valuenow', '0');
  await expect(bars.nth(1)).toHaveAttribute('aria-valuenow', '100');
  await expect(page.getByText('Preparing scan', { exact: true })).toBeVisible();
});

test('severity deltas skip failed runs, retain zero counts and label partial baselines', async ({ page }) => {
  // Deliberately unordered: report chronology, not response order, determines the baseline.
  await openProject(page, () => [
    job('4', 'succeeded', {}), job('1', 'succeeded', { critical: 2, high: 1, low: 5 }),
    job('3', 'partial', { high: 4, low: 5 }), job('2', 'failed', { high: 99 }),
  ]);
  const newest = page.getByRole('row').filter({ has: page.getByText('succeeded', { exact: true }) }).first();
  await expect(newest.locator('.finding-delta.decrease')).toHaveCount(2);
  const partial = page.getByRole('row').filter({ has: page.getByText('partial', { exact: true }) });
  await expect(partial.locator('.critical')).toContainText('0 critical');
  await expect(partial.locator('.finding-delta.increase')).toHaveAccessibleName(/high findings increased by 3/);
  await expect(partial.locator('.finding-delta.decrease')).toHaveAccessibleName(/critical findings decreased by 2/);
  await expect(partial.locator('.low .finding-delta')).toHaveCount(0);
  await expect(partial).toContainText('Comparison includes a partial scan');
  const oldest = page.getByRole('row').filter({ has: page.getByText('succeeded', { exact: true }) }).last();
  await expect(oldest.locator('.finding-delta')).toHaveCount(0);
  await page.screenshot({ path: 'test-results/finding-deltas.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('missing previous severity data does not fabricate a change', async ({ page }) => {
  await openProject(page, () => [job('2', 'succeeded', { high: 4 }), job('1', 'succeeded')]);
  await expect(page.locator('.severity .finding-delta')).toHaveCount(0);
});

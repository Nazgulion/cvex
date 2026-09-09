import { test, expect, type Page } from '@playwright/test';

async function openProject(page: Page, role = 'admin', conflict = false) {
  let jobs = [2, 1].map(id => ({ id: String(id), state: 'succeeded', created_at: `2026-09-0${id}T08:00:00Z`,
    version_label: `v${id}`, progress: 1, total: 1, trigger: 'manual', summary: { counts: { severity: { high: id === 2 ? 5 : 3 } } } }));
  let deleted = 0;
  const project = { id: 'p', company: 'Orion', name: 'Gateway', active_version_id: null, versions: [] };
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() === 'DELETE') {
      deleted++;
      if (conflict) return route.fulfill({ status: 409, json: { detail: 'This report is queued or running. Wait for it to finish before deleting it.' } });
      expect(route.request().headers()['x-csrf-token']).toBe('test');
      jobs = jobs.filter(job => job.id !== path.split('/').at(-1));
      return route.fulfill({ json: { ok: true, cleanup_pending: false } });
    }
    return route.fulfill({ json: path.endsWith('/auth/me') ? { username: 'test', role, csrf: 'test' }
      : path.endsWith('/projects') ? [project] : { ...project, jobs } });
  });
  await page.goto('/');
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'Gateway', exact: true }) }).click();
  await expect(page.getByRole('heading', { name: 'Orion — Gateway' })).toBeVisible();
  return () => deleted;
}

test('report confirmation supports cancel/Escape and recalculates comparisons after deletion', async ({ page }) => {
  const deleted = await openProject(page);
  await expect(page.locator('.severity .finding-delta')).toHaveCount(1);
  const remove = page.getByRole('button', { name: 'Delete report', exact: true }).last();
  const row = page.getByRole('row').filter({ has: page.getByRole('button', { name: 'Delete report', exact: true }) }).last();
  await expect(row.getByRole('cell').last()).toContainText('Delete report');
  await expect(row.getByRole('cell').nth(4)).not.toContainText('Delete report');
  const links = row.locator('.report-actions');
  const linksBox = await links.boundingBox();
  const removeBox = await remove.boundingBox();
  expect(removeBox!.x).toBeGreaterThanOrEqual(linksBox!.x + linksBox!.width + 24);
  await remove.click();
  const dialog = page.getByRole('dialog', { name: 'Delete this report?' });
  await expect(dialog).toContainText('Orion — Gateway');
  await expect(dialog).toContainText('SBOM version: v1');
  await expect(dialog).toContainText('This cannot be undone');
  await expect(dialog.getByRole('button', { name: 'Cancel' })).toBeFocused();
  await page.keyboard.press('Escape');
  expect(deleted()).toBe(0);
  await expect(remove).toBeFocused();
  await remove.click();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  expect(deleted()).toBe(0);
  await remove.click();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: 'test-results/delete-report-mobile.png', fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await dialog.getByRole('button', { name: 'Delete permanently' }).click();
  await expect(page.getByText('Report deleted permanently', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Delete report', exact: true })).toHaveCount(1);
  await expect(page.locator('.severity .finding-delta')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Orion — Gateway' })).toBeVisible();
  expect(deleted()).toBe(1);
});

test('report deletion is hidden from ordinary users', async ({ page }) => {
  await openProject(page, 'user');
  await expect(page.getByRole('button', { name: 'Delete report', exact: true })).toHaveCount(0);
  await expect(page.getByRole('columnheader', { name: 'ACTIONS', exact: true })).toHaveCount(0);
});

test('a report deletion error stays visible inside the confirmation', async ({ page }) => {
  await openProject(page, 'admin', true);
  await page.getByRole('button', { name: 'Delete report', exact: true }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Delete this report?' });
  await dialog.getByRole('button', { name: 'Delete permanently' }).click();
  await expect(dialog.getByRole('alert')).toContainText('Wait for it to finish');
  await expect(dialog.getByRole('button', { name: 'Cancel' })).toBeEnabled();
});

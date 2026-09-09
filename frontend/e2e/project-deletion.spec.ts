import { test, expect, type Page } from '@playwright/test';

const project = { id: 'delete-project', company: 'Orion Systems', name: 'Gateway firmware', active_version_id: null, versions: [], jobs: [] };

async function workspace(page: Page, role = 'admin', conflict = false) {
  let deleted = false;
  let requests = 0;
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/auth/me')) return route.fulfill({ json: { username: 'test', role, csrf: 'delete-test' } });
    if (path.endsWith('/projects')) return route.fulfill({ json: deleted ? [] : [project] });
    if (path.endsWith('/projects/delete-project')) {
      if (route.request().method() === 'DELETE') {
        requests++;
        expect(route.request().headers()['x-csrf-token']).toBe('delete-test');
        if (conflict) return route.fulfill({ status: 409, json: { detail: 'A report is running for this project. Wait for it to finish, then try again.' } });
        // Exercise duplicate-click protection while the destructive request is in flight.
        await new Promise(resolve => setTimeout(resolve, 300));
        deleted = true;
        return route.fulfill({ json: { ok: true, cleanup_pending: false } });
      }
      return route.fulfill({ status: deleted ? 404 : 200, json: deleted ? { detail: 'Project not found' } : project });
    }
    return route.fulfill({ json: {} });
  });
  await page.goto('/');
  await page.getByRole('button', { name: /Orion Systems/ }).click();
  await expect(page.getByRole('heading', { name: 'Orion Systems — Gateway firmware' })).toBeVisible();
  return () => requests;
}

test('admin confirms irreversible deletion; cancel and Escape are safe', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  const requests = await workspace(page);
  const remove = page.getByRole('button', { name: 'Delete project', exact: true });
  await remove.click();
  const dialog = page.getByRole('dialog', { name: 'Delete this project?' });
  await expect(dialog).toContainText('Orion Systems — Gateway firmware');
  await expect(dialog).toContainText('This cannot be undone');
  await expect(dialog.getByRole('button', { name: 'Cancel', exact: true })).toBeFocused();
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(requests()).toBe(0);
  await expect(remove).toBeFocused();
  await remove.click();
  await page.keyboard.press('Escape');
  expect(requests()).toBe(0);
  await remove.click();
  await page.screenshot({ path: 'test-results/delete-project-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  const bounds = await dialog.boundingBox();
  expect(bounds!.x).toBeGreaterThan(10);
  expect(Math.abs(bounds!.x + bounds!.width / 2 - 195)).toBeLessThan(2);
  await page.screenshot({ path: 'test-results/delete-project-mobile.png', fullPage: true });
  await dialog.getByRole('button', { name: 'Delete permanently', exact: true }).click();
  await expect(dialog.getByRole('button', { name: 'Deleting…' })).toBeDisabled();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('Project deleted permanently', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: /Orion Systems/ })).toHaveCount(0);
  expect(requests()).toBe(1);
  expect(errors).toEqual([]);
});

test('ordinary users do not see project deletion controls', async ({ page }) => {
  await workspace(page, 'user');
  await expect(page.getByRole('button', { name: 'Delete project', exact: true })).toHaveCount(0);
});

test('active-report conflict remains visible inside the dialog', async ({ page }) => {
  await workspace(page, 'admin', true);
  await page.getByRole('button', { name: 'Delete project', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Delete this project?' });
  await dialog.getByRole('button', { name: 'Delete permanently', exact: true }).click();
  await expect(dialog.getByRole('alert')).toContainText('A report is running');
  await expect(dialog.getByRole('button', { name: 'Delete permanently', exact: true })).toBeEnabled();
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Orion Systems — Gateway firmware' })).toBeVisible();
});

test('a project deleted in another tab returns to the project list', async ({ page }) => {
  await workspace(page);
  await page.route('**/api/v1/projects', route => route.fulfill({ json: [] }));
  await page.route('**/api/v1/projects/delete-project', route => route.fulfill({ status: 404, json: { detail: 'Project not found' } }));
  await expect(page.getByText('This project is no longer available.', { exact: true })).toBeVisible({ timeout: 10000 });
  await expect(page.getByRole('heading', { name: 'Orion Systems — Gateway firmware' })).toHaveCount(0);
});

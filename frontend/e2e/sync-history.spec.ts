import { test, expect, type Page } from '@playwright/test';

async function setup(page: Page) {
  let calls = 0;
  let fail = false;
  const next = '2026-09-09T12:32:00Z';
  const schedule = { enabled: true, mode: 'interval', interval_seconds: 7200, expression: '0 7 * * *', timezone: 'Europe/Belgrade', next_run: next, version: 1,
    upcoming: Array.from({length:5}, (_, i) => new Date(Date.parse(next) + i * 7200000).toISOString()), estimated: true, running: false };
  const runs = Array.from({length:26}, (_, i) => ({id: String(i), status: i === 1 ? 'failed' : 'succeeded', run_type:'sync', started_at:'2026-09-09T10:32:00Z', finished_at:'2026-09-09T10:32:21Z', processed:i === 1 ? null : 410, changed:i === 1 ? null : 300, duration_seconds:21, legacy:false, error_type:i === 1 ? 'HTTPError' : null}));
  await page.route('**/api/v1/**', route => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    let json: unknown = {};
    if (path.endsWith('/auth/me')) json = {username:'test',role:'admin',csrf:'test'};
    else if (path.endsWith('/projects')) json = [];
    else if (path.includes('/sync-history/')) {
      calls++;
      if (fail) return route.fulfill({status:503, json:{detail:'Temporarily unavailable'}});
      const cve = path.endsWith('/cve');
      const offset = Number(url.searchParams.get('offset') || 0);
      json = {source:cve?'cve':'nvd',history:cve?[]:runs.slice(offset,offset+25),latest:cve?null:runs[0],offset,limit:25,retention_days:10,server_time:'2026-09-09T11:00:00Z',
        totals:{runs:cve?0:26,succeeded:cve?0:25,failed:cve?0:1,processed:10250,changed:7500},
        source_state:{last_success:'2026-09-09T10:32:21Z',next_retry_at:cve?next:null},worker:{state:cve?'paused':'idle',stale:false,phase:'Waiting for schedule'},
        schedule:cve?{...schedule,enabled:false,upcoming:[]}:schedule};
    } else if (path.includes('/schedules/')) json = path.endsWith('/cve') ? {...schedule,enabled:false,upcoming:[]} : schedule;
    else if (path.includes('/settings/')) json = {version:1,settings:{request_timeout:'60s'},has_api_key:false};
    else if (path.endsWith('/admin/status')) json = {workers:[],sources:[],schedules:[],queue:[],jobs:[],recent_syncs:[]};
    return route.fulfill({json});
  });
  await page.goto('/');
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  await expect(page.getByRole('heading',{name:'NVD sync activity'})).toBeVisible();
  return {calls:()=>calls, fail:()=>{fail=true;}};
}

test('worker settings show measured counts, real next five and paginated 10-day history', async ({page}) => {
  const errors:string[]=[];
  page.on('pageerror', e => errors.push(e.message));
  await setup(page);
  const activity = page.getByRole('region',{name:'NVD sync activity',exact:true});
  await expect(activity.getByText('410 records pulled')).toBeVisible();
  const upcoming = activity.getByRole('list',{name:'Next five scheduled runs'});
  await expect(upcoming.locator('li')).toHaveCount(5);
  await expect(upcoming.locator('time').first()).toHaveAttribute('datetime','2026-09-09T12:32:00.000Z');
  const rows = activity.getByRole('table').locator('tbody tr');
  await expect(rows).toHaveCount(25);
  await expect(rows.first()).toContainText('110');
  await expect(rows.nth(1)).toContainText('HTTPError');
  await expect(rows.nth(1).locator('td').nth(2)).toHaveText('—');
  await page.screenshot({path:'test-results/source-history-desktop.png',fullPage:true});
  await activity.getByRole('button',{name:'Next sync history page'}).click();
  await expect(rows).toHaveCount(1);
  await expect(activity.getByText('410 records pulled')).toBeVisible();
  await expect(activity.getByRole('button',{name:'Next sync history page'})).toBeDisabled();
  await activity.getByRole('button',{name:'Previous sync history page'}).click();
  await expect(rows).toHaveCount(25);
  await page.getByRole('button',{name:'CVE synchronization',exact:true}).click();
  await expect(page.getByRole('heading',{name:'CVE sync activity'})).toBeVisible();
  await expect(page.getByRole('heading',{name:'No sync activity yet'})).toBeVisible();
  await expect(page.getByRole('list',{name:'Next five scheduled runs'})).toHaveCount(0);
  await expect(page.getByText(/Retry scheduled:/)).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('activity refresh leaves unsaved settings intact and reports refresh errors', async ({page}) => {
  const state = await setup(page);
  await page.getByLabel('Interval in seconds').fill('9000');
  const before = state.calls();
  await expect.poll(state.calls,{timeout:10000}).toBeGreaterThan(before);
  await expect(page.getByLabel('Interval in seconds')).toHaveValue('9000');
  state.fail();
  await expect(page.getByRole('alert')).toContainText('Showing the last received data.',{timeout:10000});
  await expect(page.getByText('410 records pulled')).toBeVisible();
});

test('worker activity fits mobile with a locally scrollable history table', async ({page}) => {
  await page.setViewportSize({width:390,height:844});
  await setup(page);
  await expect(page.getByRole('table',{name:'NVD sync history'})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  const scroll = page.getByRole('region',{name:'Scrollable sync history',exact:true});
  expect(await scroll.evaluate(el => el.scrollWidth > el.clientWidth)).toBe(true);
  await page.screenshot({path:'test-results/source-history-mobile.png',fullPage:true});
});

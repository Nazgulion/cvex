// Explicit staging acceptance: reads bootstrap credentials into memory only.
// Does not log credentials or persist browser authentication state.
import { chromium } from '@playwright/test';
import { execFileSync } from 'node:child_process';

const host = 'daki@cvex.staging.ast.local';
const credentials = execFileSync('ssh', [host, 'cat /home/daki/cvex-v2/data/workspace/initial-admin.txt'], {encoding:'utf8'});
const username = credentials.match(/^Username: (.+)$/m)[1];
const password = credentials.match(/^Password: (.+)$/m)[1];
const browser = await chromium.launch({channel:'chrome'});
try {
  const context = await browser.newContext({ignoreHTTPSErrors:true, viewport:{width:1440,height:1000}});
  const page = await context.newPage();
  const errors=[];
  page.on('pageerror', e=>errors.push(e.message));
  await page.goto('https://cvex.staging.ast.local:8443/');
  await page.getByLabel('Username',{exact:true}).fill(username);
  await page.getByLabel('Password',{exact:true}).fill(password);
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await page.getByRole('button',{name:/CompanyX_Spot_Pro/}).waitFor();
  await page.screenshot({path:'test-results/staging-projects.png',fullPage:true});
  await page.getByRole('button',{name:/CompanyX_Spot_Pro/}).click();
  const started = Date.now();
  const queuedResponse=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/runs'));
  await page.getByRole('button',{name:'Run now',exact:true}).click();
  const queued=await (await queuedResponse).json();
  await page.getByText('Report job queued',{exact:true}).waitFor();
  await page.waitForFunction(async(jobId)=>{
    const projects=await (await fetch('/api/v1/projects')).json();
    const p=projects.find(p=>p.name==='CompanyX_Spot_Pro');
    const detail=await (await fetch('/api/v1/projects/'+p.id)).json();
    return detail.jobs.some(j=>j.id===jobId&&j.state==='succeeded');
  },queued.id,{timeout:180000,polling:2000});
  const elapsed=(Date.now()-started)/1000;
  await page.getByRole('link',{name:'View HTML'}).first().waitFor();
  await page.screenshot({path:'test-results/staging-report.png',fullPage:true});
  const popup=page.waitForEvent('popup');
  await page.getByRole('link',{name:'View HTML'}).first().click();
  const report=await popup;await report.waitForLoadState();
  if(!(await report.locator('body').innerText()).includes('CompanyX_Spot_Pro'))throw new Error('Report has wrong product');
  await report.close();
  await page.getByRole('button',{name:'Architecture',exact:true}).click();
  await page.getByText('PostgreSQL intelligence').waitFor();
  await page.screenshot({path:'test-results/staging-architecture.png',fullPage:true});
  const status=await page.evaluate(async()=>await (await fetch('/api/v1/admin/status')).json());
  if(errors.length)throw new Error(errors.join('\n'));
  console.log(JSON.stringify({browser_errors:errors,report_workflow_seconds:elapsed,workers:status.workers.map(w=>({name:w.name,state:w.state,stale:w.stale})),schedules:status.schedules},null,2));
} finally {await browser.close();}

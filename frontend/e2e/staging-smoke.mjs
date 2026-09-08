// Explicit staging acceptance: reads bootstrap credentials into memory only.
// Does not log credentials or persist browser authentication state.
import { chromium, expect } from '@playwright/test';
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
  let jobId=process.env.CVEX_STAGING_JOB_ID;
  if(!jobId){
    const queuedResponse=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/runs'));
    await page.getByRole('button',{name:'Run now',exact:true}).click();
    jobId=(await (await queuedResponse).json()).id;
    await page.getByText('Report job queued',{exact:true}).waitFor();
  }
  if(!jobId)throw new Error('Missing report job ID');
  let verifiedJob;
  await expect.poll(async()=>{
    const projects=await (await context.request.get('https://cvex.staging.ast.local:8443/api/v1/projects')).json();
    const p=projects.find(p=>p.name==='CompanyX_Spot_Pro');
    const detail=await (await context.request.get('https://cvex.staging.ast.local:8443/api/v1/projects/'+p.id)).json();
    const job=detail.jobs.find(j=>j.id===jobId);
    verifiedJob=job;
    if(job?.state==='failed')throw new Error('Report failed: '+job.error);
    return job?.state;
  },{timeout:180000,intervals:[2000]}).toBe('succeeded');
  const elapsed=(Date.now()-started)/1000;
  const htmlLink=page.locator(`a[href="/api/v1/runs/${jobId}/artifacts/html"]`);
  await htmlLink.waitFor();
  await page.screenshot({path:'test-results/staging-report.png',fullPage:true});
  const popup=page.waitForEvent('popup');
  await htmlLink.click();
  const report=await popup;await report.waitForLoadState();
  if(!(await report.locator('body').innerText()).includes('CompanyX_Spot_Pro'))throw new Error('Report has wrong product');
  await report.close();
  const downloadEvent=page.waitForEvent('download');
  await page.locator(`a[href="/api/v1/runs/${jobId}/artifacts/html?download=true"]`).click();
  const download=await downloadEvent;
  if(await download.failure())throw new Error('HTML download failed');
  if(download.suggestedFilename()!=='findings.html')throw new Error('Unexpected report filename');
  await page.getByRole('button',{name:'Architecture',exact:true}).click();
  await page.getByText('PostgreSQL intelligence').waitFor();
  await page.screenshot({path:'test-results/staging-architecture.png',fullPage:true});
  const status=await page.evaluate(async()=>await (await fetch('/api/v1/admin/status')).json());
  if(errors.length)throw new Error(errors.join('\n'));
  console.log(JSON.stringify({browser_errors:errors,report_job_id:jobId,report_duration_seconds:(Date.parse(verifiedJob.finished_at)-Date.parse(verifiedJob.started_at))/1000,verification_wait_seconds:elapsed,workers:status.workers.map(w=>({name:w.name,state:w.state,stale:w.stale})),schedules:status.schedules},null,2));
} finally {await browser.close();}

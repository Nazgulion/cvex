import type { ReportJob } from "./types";

/** Failed/in-flight jobs are not comparison baselines. Oldest retained report has none. */
export function previousReports(jobs: ReportJob[]) {
  const result = new Map<string, ReportJob>();
  let previous: ReportJob | undefined;
  const published = jobs
    .filter((job) => ["succeeded", "partial"].includes(job.state))
    .sort(
      (a, b) =>
        Date.parse(a.created_at) - Date.parse(b.created_at) ||
        a.id.localeCompare(b.id),
    );
  for (const job of published) {
    if (previous) result.set(job.id, previous);
    previous = job;
  }
  return result;
}

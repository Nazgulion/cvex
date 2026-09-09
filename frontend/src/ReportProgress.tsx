import type { ReportJob } from "./types";

/** Percent measures assessed components, not a fabricated estimate of export time. */
export function ReportProgress({ job }: { job: ReportJob }) {
  if (!["queued", "scanning", "exporting"].includes(job.state)) return null;
  const total = Math.max(0, job.total ?? 0);
  const done = Math.min(total, Math.max(0, job.progress || 0));
  const percent =
    job.state === "queued"
      ? 0
      : job.state === "exporting"
        ? 100
        : total > 0
          ? Math.floor((done / total) * 100)
          : 0;
  const label =
    job.state === "queued"
      ? "Waiting to start"
      : job.state === "exporting"
        ? "Scan complete · writing reports"
        : total > 0
          ? `${done} / ${total} components`
          : "Preparing scan";
  return (
    <div className="report-progress">
      <div className="report-progress-label">
        <span>{label}</span>
        <strong>{percent}%</strong>
      </div>
      <div
        className="report-progress-track"
        role="progressbar"
        aria-label="Component scan progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
        aria-valuetext={`${percent}% · ${label}`}
      >
        <div
          className="report-progress-fill"
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}

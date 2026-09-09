import React from "react";
import { Folder, ArrowUp, ArrowDown } from "lucide-react";
import type { Summary, ReportJob } from "./types";
export const when = (value?: string | null) =>
  value ? new Date(value).toLocaleString() : "—";
export const inZone = (value: string, zone: string) => {
  try {
    return new Date(value).toLocaleString(undefined, { timeZone: zone });
  } catch {
    return when(value);
  }
};
export const bytes = (value?: number) =>
  value ? (value / 1024 ** 3).toFixed(1) + " GB" : "—";
export function Badge({ state }: { state: string }) {
  return (
    <span className={"badge " + state}>
      <i />
      {state?.replaceAll("_", " ") || "not run"}
    </span>
  );
}
export function Empty({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty">
      <Folder size={30} />
      <h3>{title}</h3>
      <p>{detail}</p>
    </div>
  );
}
export function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}

export function Stat({
  title,
  value,
  detail,
}: {
  title: string;
  value: React.ReactNode;
  detail: string;
}) {
  return (
    <div className="stat">
      <small>{title}</small>
      <strong>{value}</strong>
      <span>{detail}</span>
    </div>
  );
}
export function Severity({
  summary,
  previous,
  partial = false,
}: {
  summary: Summary | null;
  previous?: ReportJob;
  partial?: boolean;
}) {
  if (!summary) return <span className="muted">—</span>;
  const counts = summary.counts?.severity || {};
  const baseline = previous?.summary?.counts?.severity;
  const comparable = summary.counts?.severity != null && baseline != null;
  const keys = [
    ...new Set([
      ...Object.keys(counts),
      ...(comparable ? Object.keys(baseline) : []),
    ]),
  ];
  const order = ["critical", "high", "medium", "low", "unknown"];
  keys.sort(
    (a, b) =>
      (order.indexOf(a) < 0 ? 99 : order.indexOf(a)) -
        (order.indexOf(b) < 0 ? 99 : order.indexOf(b)) || a.localeCompare(b),
  );
  const stale = Object.values(summary.source_freshness || {}).some((s) =>
    ["stale", "failed", "degraded"].includes(s?.health || ""),
  );
  return (
    <>
      <div className="severity">
        {keys.length ? (
          keys.map((k) => {
            const value = counts[k] ?? 0;
            const delta = comparable ? value - (baseline[k] ?? 0) : 0;
            const description = `${k} findings ${delta > 0 ? "increased" : "decreased"} by ${Math.abs(delta)} compared with ${when(previous?.created_at)} (${previous?.version_label})`;
            return (
              <span
                key={k}
                className={`severity-count ${k.toLowerCase()}`}
                title={k}
              >
                {value} {k}
                {delta !== 0 && (
                  <span
                    className={`finding-delta ${delta > 0 ? "increase" : "decrease"}`}
                    title={description}
                    role="img"
                    aria-label={description}
                  >
                    {delta > 0 ? (
                      <ArrowUp size={12} aria-hidden="true" />
                    ) : (
                      <ArrowDown size={12} aria-hidden="true" />
                    )}
                    {Math.abs(delta)}
                  </span>
                )}
              </span>
            );
          })
        ) : (
          <span>No findings</span>
        )}
      </div>
      {comparable && (partial || previous?.state === "partial") && (
        <small className="warning">Comparison includes a partial scan</small>
      )}
      {stale && <small className="warning">Source freshness warning</small>}
    </>
  );
}

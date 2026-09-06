import React from "react";
import { Folder } from "lucide-react";
import type { Summary } from "./types";
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
export function Severity({ summary }: { summary: Summary | null }) {
  if (!summary) return <span className="muted">—</span>;
  const counts = summary.counts?.severity || {};
  const stale = Object.values(summary.source_freshness || {}).some((s) =>
    ["stale", "failed", "degraded"].includes(s?.health || ""),
  );
  return (
    <>
      <div className="severity">
        {Object.keys(counts).length ? (
          Object.entries(counts).map(([k, v]) => (
            <span key={k} className={k.toLowerCase()} title={k}>
              {String(v)} {k}
            </span>
          ))
        ) : (
          <span>No findings</span>
        )}
      </div>
      {stale && <small className="warning">Source freshness warning</small>}
    </>
  );
}

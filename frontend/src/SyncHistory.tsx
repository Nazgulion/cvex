import { Clock3, RefreshCw } from "lucide-react";
import { Badge, when } from "./ui";
import type { Status } from "./types";

const number = (value: string | number | null) =>
  value === null ? "—" : Number(value).toLocaleString();

export function SyncHistory({ status }: { status: Status | null }) {
  return (
    <section
      className="sync-history"
      aria-label="Source synchronization history"
    >
      <div className="section-bar">
        <div>
          <span className="eyebrow">INTELLIGENCE UPDATES</span>
          <h2>Source sync history</h2>
        </div>
        <span className="history-note">
          <Clock3 size={14} />
          Latest 12 ingestion runs
        </span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Source</th>
              <th>Started</th>
              <th>Finished</th>
              <th>Duration</th>
              <th>Processed</th>
              <th>Added / updated</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {status?.recent_syncs?.map((run) => (
              <tr key={run.id}>
                <td>
                  <span className="source-label">
                    <RefreshCw size={14} />
                    {run.source.toUpperCase()}
                  </span>
                </td>
                <td>{when(run.started_at)}</td>
                <td>{when(run.finished_at)}</td>
                <td className="numeric">
                  {run.duration_seconds === null
                    ? "In progress"
                    : `${Number(run.duration_seconds).toFixed(1)}s`}
                </td>
                <td className="numeric">{number(run.processed)}</td>
                <td className="numeric">{number(run.changed)}</td>
                <td>
                  <Badge state={run.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!status?.recent_syncs?.length && (
          <div className="empty">
            <RefreshCw size={24} />
            <h3>No sync history yet</h3>
            <p>Completed and running ingestion records will appear here.</p>
          </div>
        )}
      </div>
      <p className="history-note">
        Changed records include additions and updates. Duration measures
        ingestion; CVE Git preparation happens before its ingestion run. Missing
        counts are shown as —, not zero.
      </p>
    </section>
  );
}

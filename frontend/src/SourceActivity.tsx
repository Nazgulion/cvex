import { useEffect, useState } from "react";
import { ArrowLeft, ArrowRight, Clock3, RefreshCw } from "lucide-react";
import { api } from "./api";
import { Badge, Empty, inZone } from "./ui";
import type { SyncHistory } from "./types";
import { useVisibility } from "./useVisibility";

const number = (value: number | null | undefined) =>
  value == null ? "—" : value.toLocaleString();
const duration = (value: number | null | undefined) =>
  value == null
    ? "—"
    : value < 60
      ? `${value.toFixed(1)} s`
      : `${Math.floor(value / 60)}m ${Math.round(value % 60)}s`;

export function SourceActivity({
  source,
  refreshVersion,
}: {
  source: string;
  refreshVersion?: number;
}) {
  const [data, setData] = useState<SyncHistory | null>(null);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const visible = useVisibility();
  useEffect(() => {
    if (!visible) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    setLoading(true);
    const refresh = async () => {
      try {
        const value = await api<SyncHistory>(
          `/admin/sync-history/${source}?offset=${offset}`,
          "GET",
          undefined,
          controller.signal,
        );
        if (!controller.signal.aborted) {
          if (offset && offset >= value.totals.runs)
            setOffset(
              Math.max(0, Math.ceil(value.totals.runs / value.limit) - 1) *
                value.limit,
            );
          else setData(value);
          setError("");
        }
      } catch (e) {
        if (!controller.signal.aborted) setError((e as Error).message);
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
          timer = setTimeout(refresh, 5000);
        }
      }
    };
    void refresh();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [source, offset, refreshVersion, visible]);
  const zone = data?.schedule?.timezone || "Europe/Belgrade";
  const time = (value?: string | null) => (value ? inZone(value, zone) : "—");
  const next = data?.schedule?.upcoming || [];
  return (
    <section
      className="panel sync-activity"
      aria-label={`${source.toUpperCase()} sync activity`}
    >
      <div className="section-bar">
        <div>
          <span className="eyebrow">SOURCE INTELLIGENCE</span>
          <h2>{source.toUpperCase()} sync activity</h2>
        </div>
        <Badge
          state={
            data?.worker?.stale ? "stale" : data?.worker?.state || "unknown"
          }
        />
      </div>
      <p className="sync-refresh">
        <RefreshCw size={13} /> Refreshes every 5 seconds · {zone}
        {data && ` · checked ${time(data.server_time)}`}
      </p>
      {error && (
        <div className="alert" role="alert">
          Could not refresh sync activity: {error}.{" "}
          {data && "Showing the last received data."}
        </div>
      )}
      {!data && !error && <p role="status">Loading worker activity…</p>}
      {data && (
        <>
          <div className="sync-metrics">
            <div>
              <small>Last successful sync</small>
              <strong>{time(data.source_state?.last_success)}</strong>
              <span>{data.worker?.phase || "Waiting for worker"}</span>
            </div>
            <div>
              <small>Latest completed attempt</small>
              <strong>{number(data.latest?.processed)} records pulled</strong>
              <span>
                {number(data.latest?.changed)} new / updated ·{" "}
                {duration(data.latest?.duration_seconds)}
                {data.latest && ` · ${data.latest.status}`}
              </span>
            </div>
            <div>
              <small>Last 10 days</small>
              <strong>{number(data.totals.succeeded)} successful runs</strong>
              <span>
                {number(data.totals.failed)} failed / interrupted ·{" "}
                {number(data.totals.processed)} records processed
              </span>
            </div>
          </div>
          <div className="sync-upcoming">
            <div>
              <h3>
                <Clock3 size={17} /> Next five scheduled runs
              </h3>
              <p>
                {!data.schedule?.enabled
                  ? "Schedule paused. No automatic runs are scheduled."
                  : data.schedule.running
                    ? "Sync in progress. These times are projections; the schedule updates when it finishes."
                    : data.schedule.estimated
                      ? "The first time is saved. Later times are estimates: intervals start after each sync finishes."
                      : "Saved cron schedule. Actual starts depend on worker availability."}
              </p>
              {data.schedule?.enabled && data.source_state?.next_retry_at && (
                <p className="warning">
                  Retry scheduled: {time(data.source_state.next_retry_at)}
                </p>
              )}
            </div>
            {next.length > 0 && (
              <ol aria-label="Next five scheduled runs">
                {next.map((value, i) => (
                  <li key={value}>
                    <span className="sync-slot">{i + 1}</span>
                    <time dateTime={value}>{time(value)}</time>
                    {i === 0 &&
                    !data.schedule?.running &&
                    Date.parse(value) <= Date.parse(data.server_time) ? (
                      <span className="sync-due">Due / waiting</span>
                    ) : (i > 0 || data.schedule?.running) &&
                      data.schedule?.estimated ? (
                      <small>estimated</small>
                    ) : null}
                  </li>
                ))}
              </ol>
            )}
          </div>
          <div className="section-bar">
            <h3>Sync history · last 10 days</h3>
            <small>{number(data.totals.runs)} runs</small>
          </div>
          <p className="sync-legend">
            Pulled = CVE records processed, not necessarily newly published. New
            / updated = payloads that changed. Older activity is removed
            automatically; CVEs and report evidence are preserved.
          </p>
          <div
            className="sync-table-scroll"
            tabIndex={0}
            role="region"
            aria-label="Scrollable sync history"
          >
            <table
              className="sync-table"
              aria-label={`${source.toUpperCase()} sync history`}
              aria-busy={loading}
            >
              <thead>
                <tr>
                  <th scope="col">Started / finished</th>
                  <th scope="col">Status</th>
                  <th scope="col">Pulled</th>
                  <th scope="col">New / updated</th>
                  <th scope="col">Unchanged</th>
                  <th scope="col">Duration</th>
                </tr>
              </thead>
              <tbody>
                {data.history.map((run) => (
                  <tr key={run.id}>
                    <td>
                      <time dateTime={run.started_at}>
                        {time(run.started_at)}
                      </time>
                      <small>
                        {run.finished_at
                          ? `Finished ${time(run.finished_at)}`
                          : run.status === "running"
                            ? "In progress"
                            : "Finish time unknown"}
                      </small>
                    </td>
                    <td>
                      <Badge state={run.status} />
                      <small>
                        {run.run_type}
                        {run.error_type && ` · ${run.error_type}`}
                      </small>
                    </td>
                    <td>{number(run.processed)}</td>
                    <td className="sync-changed">{number(run.changed)}</td>
                    <td>
                      {number(
                        run.processed == null || run.changed == null
                          ? null
                          : Math.max(0, run.processed - run.changed),
                      )}
                    </td>
                    <td>
                      {duration(run.duration_seconds)}
                      {run.legacy && (
                        <small title="Imported from earlier ingestion logs; duration may exclude upstream fetch preparation.">
                          legacy timing
                        </small>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!data.history.length && (
            <Empty
              title="No sync activity yet"
              detail="Runs from the last 10 days will appear here when this worker synchronizes."
            />
          )}
          <div className="sync-pagination">
            <small>
              {data.totals.runs
                ? `${data.offset + 1}–${Math.min(data.offset + data.limit, data.totals.runs)} of ${number(data.totals.runs)}`
                : "0 runs"}
            </small>
            <div className="button-row">
              <button
                type="button"
                aria-label="Previous sync history page"
                disabled={loading || !offset}
                onClick={() => setOffset(Math.max(0, offset - data.limit))}
              >
                <ArrowLeft size={15} /> Previous
              </button>
              <button
                type="button"
                aria-label="Next sync history page"
                disabled={loading || offset + data.limit >= data.totals.runs}
                onClick={() => setOffset(offset + data.limit)}
              >
                Next <ArrowRight size={15} />
              </button>
            </div>
          </div>
        </>
      )}
    </section>
  );
}

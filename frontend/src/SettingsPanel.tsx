import { useEffect, useState } from "react";
import { api } from "./api";
import { Badge, Field, inZone } from "./ui";
import type { Project, Schedule, WorkerSettings } from "./types";
import { SourceActivity } from "./SourceActivity";
export function SettingsPanel({
  target,
  projects,
  onSelect,
  act,
  busy,
}: {
  target: string;
  projects: Project[];
  onSelect: (s: string) => void;
  act: (f: () => Promise<unknown>, m?: string) => Promise<void>;
  busy: boolean;
}) {
  const [schedule, setSchedule] = useState<Schedule | null>(null),
    [settings, setSettings] = useState<WorkerSettings | null>(null),
    [error, setError] = useState("");
  const source = ["nvd", "cve"].includes(target),
    schedulable = source || target.startsWith("project:");
  useEffect(() => {
    const controller = new AbortController();
    setSchedule(null);
    setSettings(null);
    setError("");
    const failed = (e: Error) => {
      if (!controller.signal.aborted) setError(e.message);
    };
    if (schedulable)
      api<Schedule>("/schedules/" + target, "GET", undefined, controller.signal)
        .then((value) => {
          if (!controller.signal.aborted) setSchedule(value);
        })
        .catch(failed);
    if (source)
      api<WorkerSettings>(
        "/settings/" + target,
        "GET",
        undefined,
        controller.signal,
      )
        .then((value) => {
          if (!controller.signal.aborted) setSettings(value);
        })
        .catch(failed);
    return () => controller.abort();
  }, [target]);
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">ADMINISTRATION</span>
          <h1>
            Settings<span className="heading-dot">.</span>
          </h1>
          <p>Control when work happens. Changes apply between worker cycles.</p>
        </div>
      </div>
      <div className="settings-layout">
        <div className="settings-nav">
          <small>SOURCE WORKERS</small>
          {["nvd", "cve"].map((s) => (
            <button
              className={target === s ? "active" : ""}
              key={s}
              onClick={() => onSelect(s)}
            >
              {s.toUpperCase()} synchronization
            </button>
          ))}
          <small>PROJECT SCHEDULES</small>
          {projects.map((p) => (
            <button
              className={target === "project:" + p.id ? "active" : ""}
              key={p.id}
              onClick={() => onSelect("project:" + p.id)}
            >
              {p.company} — {p.name}
            </button>
          ))}
        </div>
        <div className="settings-content">
          {error && <div className="alert">{error}</div>}
          {source && (
            <SourceActivity
              key={target}
              source={target}
              refreshVersion={schedule?.version}
            />
          )}
          {!schedulable && (
            <div className="panel">
              <h2>{target}</h2>
              <p>
                {target === "report-worker"
                  ? "One report executes at a time. Jobs run against current local data and automatically export their results."
                  : target === "queue"
                    ? "Project schedules and Run now requests feed the durable report queue. Each project can have one queued or active job."
                    : target === "database"
                      ? "Shared PostgreSQL storage contains compact NVD/CVE intelligence, project metadata, and report history."
                      : target === "storage"
                        ? "The newest 30 successful reports are retained per project. Uploaded SBOM versions remain available."
                        : "The scheduler checks enabled project schedules every two seconds."}
              </p>
              <p>
                Use the project schedule controls to configure report
                generation.
              </p>
            </div>
          )}
          {schedule && (
            <form
              className="panel"
              onSubmit={(e) => {
                e.preventDefault();
                act(async () => {
                  const {
                    enabled,
                    mode,
                    expression,
                    timezone,
                    interval_seconds,
                  } = schedule;
                  setSchedule(
                    await api<Schedule>("/schedules/" + target, "PUT", {
                      enabled,
                      mode,
                      expression,
                      timezone,
                      interval_seconds: Number(interval_seconds),
                    }),
                  );
                }, "Schedule saved");
              }}
            >
              <div className="section-bar">
                <h2>
                  {source
                    ? target.toUpperCase() + " synchronization"
                    : "Scan & export schedule"}
                </h2>
                <Badge state={schedule.enabled ? "enabled" : "paused"} />
              </div>
              <Field label="Scheduling">
                <select
                  value={String(schedule.enabled)}
                  onChange={(e) =>
                    setSchedule({
                      ...schedule,
                      enabled: e.target.value === "true",
                    })
                  }
                >
                  <option value="false">Paused</option>
                  <option value="true">Enabled</option>
                </select>
              </Field>
              {source && (
                <Field label="Schedule type">
                  <select
                    value={schedule.mode}
                    onChange={(e) =>
                      setSchedule({
                        ...schedule,
                        mode: e.target.value as Schedule["mode"],
                      })
                    }
                  >
                    <option value="interval">Repeating interval</option>
                    <option value="cron">Cron schedule</option>
                  </select>
                </Field>
              )}
              {schedule.mode === "interval" ? (
                <Field label="Interval in seconds">
                  <input
                    type="number"
                    min={60}
                    value={schedule.interval_seconds}
                    onChange={(e) =>
                      setSchedule({
                        ...schedule,
                        interval_seconds: e.target.value,
                      })
                    }
                  />
                </Field>
              ) : (
                <Field label="Cron expression · minute hour day month weekday">
                  <input
                    value={schedule.expression}
                    onChange={(e) =>
                      setSchedule({ ...schedule, expression: e.target.value })
                    }
                    placeholder="0 7 * * *"
                  />
                  <small>Example: 0 7 * * * runs daily at 07:00.</small>
                </Field>
              )}
              <Field label="Timezone">
                <input
                  value={schedule.timezone}
                  onChange={(e) =>
                    setSchedule({ ...schedule, timezone: e.target.value })
                  }
                />
              </Field>
              <p>
                Scheduled time queues the job. Actual start depends on available
                capacity. Reports use local data even if a source is stale.
              </p>
              <button disabled={busy} className="primary">
                Save schedule
              </button>
              {!source && (
                <div className="upcoming">
                  <small>NEXT FIVE OCCURRENCES · SAVED CONFIGURATION</small>
                  {schedule.upcoming?.map((d: string) => (
                    <div key={d}>
                      {inZone(d, schedule.timezone)}{" "}
                      <span>{schedule.timezone}</span>
                    </div>
                  ))}
                  {!schedule.enabled && (
                    <p>Schedule paused. No automatic runs are scheduled.</p>
                  )}
                </div>
              )}
            </form>
          )}
          {settings && (
            <form
              className="panel"
              onSubmit={(e) => {
                e.preventDefault();
                const f = new FormData(e.currentTarget);
                const values = Object.fromEntries(f);
                if (!values.api_key) delete values.api_key;
                act(
                  async () =>
                    setSettings(
                      await api<WorkerSettings>(
                        "/settings/" + target,
                        "PUT",
                        values,
                      ),
                    ),
                  "Worker settings saved",
                );
              }}
            >
              <div className="section-bar">
                <h2>Worker configuration</h2>
                <small>Saved v{settings.version}</small>
              </div>
              <div className="form-grid">
                {Object.entries(settings.settings)
                  .filter(([k]) => target === "nvd" || !k.includes("pause"))
                  .map(([k, v]) => (
                    <Field
                      key={target + k + settings.version}
                      label={k.replaceAll("_", " ")}
                    >
                      <input
                        name={k}
                        defaultValue={String(v || "2s")}
                        required
                      />
                    </Field>
                  ))}
              </div>
              {target === "nvd" && (
                <Field
                  label={
                    "NVD API key · " +
                    (settings.has_api_key ? "configured" : "not configured")
                  }
                >
                  <input
                    name="api_key"
                    type="password"
                    autoComplete="new-password"
                    placeholder="Leave blank to keep existing key"
                  />
                </Field>
              )}
              <div className="button-row">
                <button disabled={busy} className="primary">
                  Save worker settings
                </button>
                {target === "nvd" && settings.has_api_key && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() =>
                      act(
                        async () =>
                          setSettings(
                            await api<WorkerSettings>(
                              "/settings/" + target,
                              "PUT",
                              { ...settings.settings, api_key: "" },
                            ),
                          ),
                        "API key cleared",
                      )
                    }
                  >
                    Clear API key
                  </button>
                )}
              </div>
            </form>
          )}
        </div>
      </div>
    </>
  );
}

import React, { lazy, Suspense, useEffect, useState, useRef } from "react";
import { createRoot } from "react-dom/client";
import {
  Shield,
  Folder,
  Activity,
  Workflow,
  Settings,
  Users,
  Sun,
  Moon,
  LogOut,
  Plus,
  ArrowUpRight,
  Download,
  Play,
  Upload,
  ChevronRight,
  Search,
  Clock,
  Database,
  Radio,
  Check,
  X,
  FileCheck2,
  LoaderCircle,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import "./style.css";

import { api, ApiError, setCsrf } from "./api";
import { Badge, Empty, Field, Stat, Severity, when, bytes } from "./ui";
import { useVisibility } from "./useVisibility";
import { SyncHistory } from "./SyncHistory";
import { Dialog } from "./Dialog";
const Architecture = lazy(() =>
  import("./Architecture").then((module) => ({ default: module.Architecture })),
);
import { SettingsPanel } from "./SettingsPanel";
import type { User, Project, ProjectDetail, Status, AuditEvent } from "./types";

function App() {
  const visible = useVisibility();
  const [user, setUser] = useState<User | null>(null),
    [loading, setLoading] = useState(true),
    [page, setPage] = useState("projects"),
    [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [theme, setTheme] = useState(localStorage.getItem("cvex-theme") || "dark");
  const [projects, setProjects] = useState<Project[]>([]),
    [project, setProject] = useState<ProjectDetail | null>(null),
    [search, setSearch] = useState(""),
    [create, setCreate] = useState(false);
  const [deletingProject, setDeletingProject] = useState<ProjectDetail | null>(
    null,
  );
  const [deleteError, setDeleteError] = useState("");
  const [status, setStatus] = useState<Status | null>(null),
    [connected, setConnected] = useState(false),
    [settingsTarget, setSettingsTarget] = useState("nvd");
  const [activity, setActivity] = useState<AuditEvent[]>([]),
    [users, setUsers] = useState<User[]>([]),
    [busy, setBusy] = useState(false);
  const activeSelection = useRef(selected),
    activeUser = useRef(user);
  activeSelection.current = selected;
  activeUser.current = user;
  const clearSession = () => {
    activeUser.current = null;
    refreshRequest.current?.abort();
    setCsrf("");
    setUser(null);
    setSelected(null);
    setProject(null);
    setStatus(null);
    setPage("projects");
    setCreate(false);
    setDeletingProject(null);
    setDeleteError("");
    setActivity([]);
    setUsers([]);
  };
  const refreshRequest = useRef<AbortController | null>(null);
  const actionInFlight = useRef(false);
  useEffect(() => {
    const expired = () => {
      clearSession();
      setError("Your session expired. Please sign in again.");
    };
    window.addEventListener("cvex:session-expired", expired);
    return () => window.removeEventListener("cvex:session-expired", expired);
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("cvex-theme", theme);
  }, [theme]);
  useEffect(() => {
    api<User>("/auth/me")
      .then((u) => {
        setCsrf(u.csrf);
        setUser(u);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);
  const refresh = async () => {
    refreshRequest.current?.abort();
    if (!activeUser.current) return;
    const controller = new AbortController();
    refreshRequest.current = controller;
    const selection = activeSelection.current;
    try {
      const [list, detail] = await Promise.all([
        api<Project[]>("/projects", "GET", undefined, controller.signal),
        selection
          ? api<ProjectDetail>(
              "/projects/" + selection,
              "GET",
              undefined,
              controller.signal,
            ).catch((error) => {
              if (error instanceof ApiError && error.status === 404)
                return null;
              throw error;
            })
          : Promise.resolve(null),
      ]);
      if (!controller.signal.aborted && selection === activeSelection.current) {
        setProjects(list);
        setProject(detail);
        if (selection && !detail) {
          activeSelection.current = null;
          setSelected(null);
          setDeletingProject(null);
          setNotice("This project is no longer available.");
        }
      }
    } catch (e) {
      if (!controller.signal.aborted) throw e;
    }
  };
  useEffect(() => {
    setProject(null);
    if (!user || !visible) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        await refresh();
      } catch (e) {
        if (!stopped) setError((e as Error).message);
      }
      if (!stopped && page === "projects") timer = setTimeout(poll, 5000);
    };
    void poll();
    return () => {
      stopped = true;
      clearTimeout(timer);
      refreshRequest.current?.abort();
    };
  }, [user, selected, page, visible]);
  useEffect(() => {
    if (!user || user.role !== "admin" || page !== "architecture" || !visible)
      return;
    const controller = new AbortController();
    let live = false;
    const acceptStatus = (value: Status) => {
      if (!controller.signal.aborted) {
        setStatus((previous) =>
          !previous ||
          !previous.server_time ||
          value.server_time >= previous.server_time
            ? value
            : previous,
        );
      }
    };
    const events = new EventSource("/api/v1/admin/events");
    events.onmessage = (e) => {
      live = true;
      acceptStatus(JSON.parse(e.data) as Status);
      setConnected(true);
    };
    events.onerror = () => {
      live = false;
      setConnected(false);
    };
    const id = setInterval(
      () =>
        !live &&
        api<Status>("/admin/status", "GET", undefined, controller.signal)
          .then(acceptStatus)
          .catch(() => {}),
      10000,
    );
    api<Status>("/admin/status", "GET", undefined, controller.signal)
      .then(acceptStatus)
      .catch(() => {});
    return () => {
      events.close();
      controller.abort();
      clearInterval(id);
    };
  }, [user, page, visible]);
  useEffect(() => {
    if (!user) return;
    if (page === "activity")
      api<AuditEvent[]>("/activity")
        .then(setActivity)
        .catch((e) => setError(e.message));
    if (page === "users")
      api<User[]>("/users")
        .then(setUsers)
        .catch((e) => setError(e.message));
  }, [page, user]);
  const act = async (action: () => Promise<unknown>, message = "Saved") => {
    if (actionInFlight.current) return;
    actionInFlight.current = true;
    setError("");
    setBusy(true);
    try {
      await action();
      if (message) setNotice(message);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      actionInFlight.current = false;
      setBusy(false);
    }
  };
  const openSettings = (target: string) => {
    setSettingsTarget(target);
    setPage("settings");
  };
  const activeVersion = project?.versions.find(
    (version) => version.id === project.active_version_id,
  );
  const filteredProjects = projects.filter((p) =>
    `${p.company} ${p.name} ${p.filename || ""}`
      .toLowerCase()
      .includes(search.trim().toLowerCase()),
  );
  if (loading)
    return (
      <div className="splash">
        <Shield className="loading-mark" />
        Loading workspace…
      </div>
    );
  if (!user)
    return (
      <div className="login-layout">
        <div className="login-story">
          <div className="brand">
            <Shield /> CVEX<span>WORKSPACE</span>
          </div>
          <div>
            <span className="eyebrow">
              CONTINUOUS VULNERABILITY INTELLIGENCE
            </span>
            <h1>
              Know what changed.
              <br />
              <em>Know what matters.</em>
            </h1>
            <p>
              Your software inventory, current vulnerability intelligence, and
              the reports that connect them.
            </p>
            <div className="login-line">
              <span>CVE List</span>
              <span>→</span>
              <Database />
              <span>←</span>
              <span>NVD</span>
            </div>
          </div>
          <small>One workspace. A clearer picture.</small>
        </div>
        <form
          className="login-card"
          onSubmit={async (e) => {
            e.preventDefault();
            if (actionInFlight.current) return;
            actionInFlight.current = true;
            setBusy(true);
            const f = new FormData(e.currentTarget);
            try {
              const u = await api<User>(
                "/auth/login",
                "POST",
                Object.fromEntries(f),
              );
              setCsrf(u.csrf);
              setUser(u);
              setError("");
            } catch (e) {
              setError((e as Error).message);
            } finally {
              actionInFlight.current = false;
              setBusy(false);
            }
          }}
        >
          <span className="eyebrow">WELCOME BACK</span>
          <h2>Sign in to CVEX</h2>
          <p>Use your internal team account.</p>
          <Field label="Username">
            <input name="username" autoComplete="username" required />
          </Field>
          <Field label="Password">
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </Field>
          {error && <div className="alert">{error}</div>}
          <button className="primary" disabled={busy}>
            Sign in <ArrowUpRight size={16} />
          </button>
          <small>Accounts are provisioned by your administrator.</small>
        </form>
      </div>
    );
  const nav = [
    ["projects", Folder, "Projects"],
    ["activity", Activity, "Activity"],
    ...(user.role === "admin"
      ? [
          ["architecture", Workflow, "Architecture"],
          ["settings", Settings, "Settings"],
          ["users", Users, "Team"],
        ]
      : []),
  ] as const;
  const enabledSchedules = projects.filter((p) => p.schedule_enabled).length;
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Shield /> CVEX<span>WORKSPACE</span>
        </div>
        <div className="workspace-label">OPERATIONS / INTERNAL</div>
        <nav>
          {nav.map(([key, Icon, label]) => (
            <button
              key={String(key)}
              className={page === key ? "active" : ""}
              aria-current={page === key ? "page" : undefined}
              onClick={() => {
                setPage(String(key));
                setError("");
              }}
            >
              <Icon size={18} />
              {String(label)}
              {key === "projects" && (
                <span className="nav-count">{projects.length}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="subtle-card">
            <Radio size={16} />
            <span>
              Local intelligence
              <br />
              <small>NVD + CVE List</small>
            </span>
          </div>
          <button onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
            {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}{" "}
            {theme === "dark" ? "Light" : "Dark"} appearance
          </button>
          <div className="account">
            <div className="avatar">{user.username[0].toUpperCase()}</div>
            <span>
              {user.username}
              <small>{user.role}</small>
            </span>
            <button
              aria-label="Change password"
              onClick={() => setPage("account")}
            >
              <Settings size={16} />
            </button>
            <button
              aria-label="Sign out"
              onClick={() =>
                act(async () => {
                  await api("/auth/logout", "POST");
                  clearSession();
                }, "Signed out")
              }
            >
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <span>
            Workspace <ChevronRight size={13} />{" "}
            {page === "projects" && selected
              ? "Project details"
              : page[0].toUpperCase() + page.slice(1)}
          </span>
          <div>
            <span className="environment">INTERNAL WORKSPACE</span>
            <Clock size={14} />
            {new Date().toLocaleDateString(undefined, {
              month: "short",
              day: "numeric",
              year: "numeric",
            })}
          </div>
        </header>
        <div className="content">
          {error && (
            <div role="alert" className="alert">
              {error}
              <button aria-label="Dismiss error" onClick={() => setError("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {notice && (
            <div className="notice" role="status">
              <Check size={16} />
              {notice}
              <button
                aria-label="Dismiss notification"
                onClick={() => setNotice("")}
              >
                <X size={16} />
              </button>
            </div>
          )}
          {page === "projects" && !selected && (
            <>
              <div className="page-heading projects-hero">
                <div>
                  <span className="eyebrow">
                    <span className="signal-dot" /> YOUR SOFTWARE, IN FOCUS
                  </span>
                  <h1>
                    Your software.
                    <br />
                    <span className="hero-accent">A clearer picture.</span>
                  </h1>
                  <p>
                    A living view of your software inventory and vulnerability
                    reports.
                  </p>
                </div>
                <button className="primary" onClick={() => setCreate(true)}>
                  <Plus size={17} />
                  New project
                </button>
              </div>
              <div className="stats">
                <Stat
                  title="PROJECTS"
                  value={projects.length}
                  detail="Company workspaces"
                />
                <Stat
                  title="SCHEDULED"
                  value={enabledSchedules}
                  detail="Automatic scan → report"
                />
                <Stat
                  title="REPORT RETENTION"
                  value="30"
                  detail="Published reports per project"
                />
              </div>
              <div className="section-bar">
                <h2>Project directory</h2>
                <div className="search">
                  <Search size={16} />
                  <input
                    aria-label="Search projects"
                    placeholder="Search company or project…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
              </div>
              <div className="project-grid">
                {filteredProjects.map((p) => (
                  <button
                    className="project-card"
                    key={p.id}
                    onClick={() => setSelected(p.id)}
                  >
                    <div className="card-top">
                      <div className="folder-icon">
                        <Folder size={23} />
                      </div>
                      <ArrowUpRight size={18} />
                    </div>
                    <small>{p.company}</small>
                    <h2>{p.name}</h2>
                    <p>
                      {p.filename || "Upload your first SBOM to get started"}
                    </p>
                    <div className="card-meta">
                      <Badge state={p.latest_state || "ready"} />
                      <span>
                        {p.active_version
                          ? `Active · ${p.active_version}`
                          : "No active version"}
                      </span>
                    </div>
                    <footer>
                      <Clock size={13} />
                      {p.schedule_enabled
                        ? "Next " + when(p.next_run)
                        : "Manual scans · schedule disabled"}
                    </footer>
                  </button>
                ))}
              </div>
              {projects.length === 0 && (
                <Empty
                  title="Your first project starts here"
                  detail="Create a company workspace, upload an SBOM, and generate your first findings report."
                />
              )}
              {projects.length > 0 && filteredProjects.length === 0 && (
                <Empty
                  title="No matching projects"
                  detail="Try a company name, project name or SBOM filename."
                />
              )}
            </>
          )}
          {page === "projects" && selected && project?.id !== selected && (
            <div className="loading-panel" role="status">
              <LoaderCircle className="spin" size={22} />
              <span>Loading project…</span>
              <button onClick={() => setSelected(null)}>
                Back to projects
              </button>
            </div>
          )}
          {page === "projects" && selected && project?.id === selected && (
            <>
              <button
                className="back"
                onClick={() => {
                  setSelected(null);
                  setProject(null);
                }}
              >
                ← All projects
              </button>
              <div className="page-heading">
                <div>
                  <span className="eyebrow">PROJECT WORKSPACE</span>
                  <h1>
                    {project.company} <span className="muted">—</span>{" "}
                    {project.name}
                  </h1>
                  <p>
                    Versioned software inventory. Reports built from current
                    local intelligence.
                  </p>
                </div>
                <div className="button-row">
                  {user.role === "admin" && (
                    <button
                      className="danger-button"
                      disabled={busy}
                      onClick={() => {
                        setDeleteError("");
                        setDeletingProject(project);
                      }}
                    >
                      <Trash2 size={16} /> Delete project
                    </button>
                  )}
                  {user.role === "admin" && (
                    <button onClick={() => openSettings("project:" + selected)}>
                      <Clock size={16} />
                      Schedule
                    </button>
                  )}
                  <button
                    className="primary"
                    disabled={busy || !project.active_version_id}
                    onClick={() =>
                      act(
                        () => api("/projects/" + selected + "/runs", "POST"),
                        "Report job queued",
                      )
                    }
                  >
                    <Play size={16} />
                    Run now
                  </button>
                </div>
              </div>
              <section
                className="active-sbom"
                aria-label="Selected SBOM for scanning"
              >
                <div className="active-sbom-icon">
                  <FileCheck2 size={26} />
                </div>
                <div className="active-sbom-copy">
                  <span className="eyebrow">SELECTED FOR NEW SCANS</span>
                  <h2>{activeVersion?.filename || "No SBOM selected"}</h2>
                  <p>
                    {activeVersion
                      ? `Version ${activeVersion.label} · Manual and scheduled scans use this file.`
                      : "Upload your first SPDX JSON file to start scanning."}
                  </p>
                </div>
                {activeVersion && <Badge state="active" />}
              </section>
              <div className="inventory">
                <div>
                  <span className="eyebrow">SBOM VERSIONS</span>
                  <h3>Keep your inventory current</h3>
                  <p>
                    New runs use the active version. Historical reports keep
                    their original version.
                  </p>
                </div>
                <form
                  className="upload-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    const f = new FormData(e.currentTarget);
                    const label = String(f.get("label") || "");
                    f.delete("label");
                    act(
                      () =>
                        api(
                          "/projects/" +
                            selected +
                            "/versions?label=" +
                            encodeURIComponent(label),
                          "POST",
                          f,
                        ),
                      "SBOM uploaded",
                    );
                  }}
                >
                  <input
                    aria-label="Version label"
                    name="label"
                    placeholder="Version label, e.g. 2.4.0"
                    required
                  />
                  <small className="upload-hint">
                    A label for this software release, not an API key.
                  </small>
                  <input
                    aria-label="SPDX JSON file"
                    name="file"
                    type="file"
                    accept=".json,application/json"
                    required
                  />
                  <button disabled={busy}>
                    <Upload size={16} />
                    Upload SPDX JSON
                  </button>
                </form>
              </div>
              <div className="versions">
                {project.versions.map((v) => (
                  <div
                    key={v.id}
                    className={
                      v.id === project.active_version_id
                        ? "version-selected"
                        : ""
                    }
                  >
                    <div>
                      <strong>{v.label}</strong>
                      <small>
                        {v.filename} · {when(v.created_at)}
                      </small>
                    </div>
                    {v.id === project.active_version_id ? (
                      <Badge state="active" />
                    ) : (
                      <button
                        disabled={busy}
                        onClick={() =>
                          act(
                            () =>
                              api(
                                `/projects/${selected}/versions/${v.id}/activate`,
                                "POST",
                              ),
                            "Active version updated",
                          )
                        }
                      >
                        Make active
                      </button>
                    )}
                  </div>
                ))}
              </div>
              <div className="section-bar">
                <h2>
                  Recent scans{" "}
                  <span className="count">{project.jobs.length}</span>
                </h2>
                <small>Newest 30 published reports retained</small>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>SCAN TIME</th>
                      <th>SBOM VERSION</th>
                      <th>STATUS</th>
                      <th>FINDINGS</th>
                      <th>REPORT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {project.jobs.map((j) => (
                      <tr key={j.id}>
                        <td>
                          <strong>{when(j.created_at)}</strong>
                          <small>
                            {j.trigger}
                            {j.finished_at && j.started_at
                              ? " · " +
                                Math.round(
                                  (new Date(j.finished_at).getTime() -
                                    new Date(j.started_at).getTime()) /
                                    1000,
                                ) +
                                "s"
                              : ""}
                            {j.scheduled_at
                              ? " · due " + when(j.scheduled_at)
                              : ""}
                          </small>
                        </td>
                        <td>{j.version_label}</td>
                        <td>
                          <Badge state={j.state} />
                          {j.total && j.state === "scanning" ? (
                            <small>
                              {j.progress} / {j.total} components
                            </small>
                          ) : null}
                          {j.error && (
                            <small className="danger">{j.error}</small>
                          )}
                        </td>
                        <td>
                          <Severity summary={j.summary} />
                        </td>
                        <td>
                          {["succeeded", "partial"].includes(j.state) ? (
                            <div className="report-actions">
                              <a
                                href={`/api/v1/runs/${j.id}/artifacts/html`}
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                <ArrowUpRight size={15} />
                                View HTML
                              </a>
                              <a
                                aria-label="Download HTML"
                                href={`/api/v1/runs/${j.id}/artifacts/html?download=true`}
                              >
                                <Download size={15} />
                              </a>
                              <a
                                href={`/api/v1/runs/${j.id}/artifacts/csv?download=true`}
                              >
                                CSV
                              </a>
                              <a
                                href={`/api/v1/runs/${j.id}/artifacts/json?download=true`}
                              >
                                JSON
                              </a>
                            </div>
                          ) : (
                            <span className="muted">
                              Available after export
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!project.jobs.length && (
                  <Empty
                    title="No scans yet"
                    detail="Run a scan now, or ask an admin to set a recurring schedule."
                  />
                )}
              </div>
            </>
          )}
          {page === "architecture" && (
            <>
              <div className="page-heading">
                <div>
                  <span className="eyebrow">SYSTEM OBSERVABILITY</span>
                  <h1>
                    Architecture<span className="heading-dot">.</span>
                  </h1>
                  <p>
                    Two independent workflows. One shared intelligence database.
                  </p>
                </div>
                <Badge state={connected ? "live" : "reconnecting"} />
              </div>
              <div className="stats">
                <Stat
                  title="DATABASE"
                  value={bytes(status?.database_bytes)}
                  detail="Compact source intelligence"
                />
                <Stat
                  title="REPORT QUEUE"
                  value={
                    status?.queue
                      ?.filter((q) => q.state === "queued")
                      .reduce((n: number, q) => n + Number(q.count), 0) || 0
                  }
                  detail="Awaiting report executor"
                />
                <Stat
                  title="REPORT STORAGE"
                  value={bytes(
                    status?.workers?.find((w) => w.name === "storage")?.details
                      ?.report_bytes,
                  )}
                  detail="Retained project artifacts"
                />
                <Stat
                  title="DISK AVAILABLE"
                  value={bytes(status?.disk_free_bytes)}
                  detail={"of " + bytes(status?.disk_total_bytes)}
                />
              </div>
              <Suspense
                fallback={
                  <div className="loading-panel" role="status">
                    <LoaderCircle className="spin" />
                    Loading architecture…
                  </div>
                }
              >
                <Architecture
                  status={status}
                  onSelect={openSettings}
                  theme={theme === "light" ? "light" : "dark"}
                />
              </Suspense>
              <SyncHistory status={status} />
              <div className="section-bar">
                <h2>Report queue</h2>
                <small>One active job per project</small>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>PROJECT</th>
                      <th>STATE</th>
                      <th>QUEUED AT</th>
                      <th>PROGRESS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {status?.jobs?.map((j) => (
                      <tr key={j.id}>
                        <td>
                          {j.company} — {j.name}
                        </td>
                        <td>
                          <Badge state={j.state} />
                        </td>
                        <td>{when(j.created_at)}</td>
                        <td>
                          {j.total
                            ? `${j.progress} / ${j.total} components`
                            : "Waiting"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!status?.jobs?.length && (
                  <Empty
                    title="Queue is clear"
                    detail="Scheduled and manual reports will appear here."
                  />
                )}
              </div>
              <div className="section-bar">
                <h2>Worker activity</h2>
                <small>Measured heartbeats · updated every 3 seconds</small>
              </div>
              <div className="worker-grid">
                {status?.workers?.map((w) => (
                  <button
                    className="worker-card"
                    key={w.name}
                    onClick={() => openSettings(w.name)}
                  >
                    <div>
                      <h3>{w.name}</h3>
                      <Badge state={w.stale ? "stale" : w.state} />
                    </div>
                    <p>{w.phase || w.details?.phase || "Waiting"}</p>
                    <small>Heartbeat {when(w.heartbeat_at)}</small>
                    {w.details?.processed !== undefined && (
                      <small>
                        {w.details.processed.toLocaleString()} processed ·{" "}
                        {w.details.changed ?? 0} changed
                      </small>
                    )}
                    <small>Applied settings v{w.applied_version ?? "—"}</small>
                    {status.sources
                      ?.filter((s) => s.source === w.name)
                      .map((s) => (
                        <div className="source-details" key={s.source}>
                          <small>Last success {when(s.last_success)}</small>
                          <small>
                            Next run{" "}
                            {when(
                              status.schedules?.find((x) => x.target === w.name)
                                ?.next_run,
                            )}
                          </small>
                          {s.error_count > 0 && (
                            <small className="warning">
                              {s.error_type || "Synchronization error"} ·{" "}
                              {s.error_count} failures · retry{" "}
                              {when(s.next_retry_at)}
                            </small>
                          )}
                        </div>
                      ))}
                  </button>
                ))}
              </div>
            </>
          )}
          {page === "account" && (
            <div className="panel">
              <h2>Change your password</h2>
              <p>
                All sessions will be signed out after changing your password.
              </p>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const body = Object.fromEntries(
                    new FormData(e.currentTarget),
                  );
                  act(async () => {
                    await api("/auth/password", "POST", body);
                    clearSession();
                  }, "Password changed. Sign in again.");
                }}
              >
                <Field label="Current password">
                  <input
                    name="current_password"
                    type="password"
                    autoComplete="current-password"
                    required
                  />
                </Field>
                <Field label="New password">
                  <input
                    name="new_password"
                    type="password"
                    minLength={12}
                    autoComplete="new-password"
                    required
                  />
                </Field>
                <button className="primary" disabled={busy}>
                  Change password
                </button>
              </form>
            </div>
          )}
          {page === "settings" && (
            <SettingsPanel
              key={settingsTarget}
              target={settingsTarget}
              projects={projects}
              onSelect={setSettingsTarget}
              act={act}
              busy={busy}
            />
          )}
          {page === "activity" && (
            <>
              <div className="page-heading">
                <div>
                  <span className="eyebrow">WORKSPACE JOURNAL</span>
                  <h1>
                    Activity<span className="heading-dot">.</span>
                  </h1>
                  <p>Account, project, report, and configuration events.</p>
                </div>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>TIME</th>
                      <th>ACTOR</th>
                      <th>EVENT</th>
                      <th>DETAILS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activity.map((a) => (
                      <tr key={a.id}>
                        <td>{when(a.created_at)}</td>
                        <td>{a.actor}</td>
                        <td>{a.action.replaceAll("_", " ")}</td>
                        <td>
                          <code>{JSON.stringify(a.details)}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {page === "users" && (
            <>
              <div className="page-heading">
                <div>
                  <span className="eyebrow">INTERNAL ACCESS</span>
                  <h1>
                    Team<span className="heading-dot">.</span>
                  </h1>
                  <p>
                    All team members share project access. Administrators manage
                    system settings.
                  </p>
                </div>
              </div>
              <div className="inventory">
                <form
                  className="inline-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    const f = Object.fromEntries(new FormData(e.currentTarget));
                    act(async () => {
                      await api("/users", "POST", f);
                      setUsers(await api<User[]>("/users"));
                    }, "Account created");
                  }}
                >
                  <Field label="Username">
                    <input name="username" required />
                  </Field>
                  <Field label="Password · 12+ characters">
                    <input
                      name="password"
                      type="password"
                      minLength={12}
                      required
                    />
                  </Field>
                  <Field label="Role">
                    <select name="role">
                      <option value="user">User</option>
                      <option value="admin">Administrator</option>
                    </select>
                  </Field>
                  <button className="primary" disabled={busy}>
                    Create account
                  </button>
                </form>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>USERNAME</th>
                      <th>ROLE</th>
                      <th>CREATED</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((u) => (
                      <tr key={u.id}>
                        <td>{u.username}</td>
                        <td>
                          <Badge state={u.role} />
                        </td>
                        <td>{when(u.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          <footer className="page-footer">
            <span>
              <Shield size={13} /> CVEX / SOFTWARE INTELLIGENCE
            </span>
            <span>Current data. Traceable reports.</span>
          </footer>
        </div>
      </main>
      {create && (
        <Dialog onClose={() => setCreate(false)} busy={busy}>
          <form
            className="modal"
            onSubmit={(e) => {
              e.preventDefault();
              const body = Object.fromEntries(new FormData(e.currentTarget));
              act(async () => {
                const p = await api<{ id: string }>("/projects", "POST", body);
                setCreate(false);
                setSelected(p.id);
              }, "Project created");
            }}
          >
            <button
              type="button"
              className="close"
              aria-label="Close"
              disabled={busy}
              onClick={() => setCreate(false)}
            >
              <X size={18} />
            </button>
            <div className="folder-icon">
              <Folder />
            </div>
            <h2 id="project-dialog-title">Create a project</h2>
            <p>A dedicated home for your SBOM versions and reports.</p>
            <Field label="Company">
              <input
                name="company"
                placeholder="Company name"
                autoFocus
                required
                maxLength={200}
              />
            </Field>
            <Field label="Project / SBOM name">
              <input
                name="name"
                placeholder="e.g. Spot Pro firmware"
                required
                maxLength={200}
              />
            </Field>
            <button className="primary" disabled={busy}>
              Create project <ChevronRight size={16} />
            </button>
          </form>
        </Dialog>
      )}
      {deletingProject && user.role === "admin" && (
        <Dialog
          titleId="delete-project-title"
          onClose={() => setDeletingProject(null)}
          busy={busy}
        >
          <div className="modal delete-project-modal">
            <div className="delete-project-icon">
              <TriangleAlert size={26} />
            </div>
            <span className="eyebrow">PERMANENT DELETION</span>
            <h2 id="delete-project-title">Delete this project?</h2>
            <p>
              Are you sure you want to delete{" "}
              <strong>
                {deletingProject.company} — {deletingProject.name}
              </strong>
              ?
            </p>
            <p>
              All uploaded files, project versions, scheduled runs, reports and
              findings for this project will be permanently removed. This cannot
              be undone.
            </p>
            <p className="muted">
              Other projects, shared SBOM catalog data and NVD/CVE
              synchronization are not affected. If a report is running, wait for
              it to finish first.
            </p>
            {deleteError && (
              <p className="delete-project-error" role="alert">
                {deleteError}
              </p>
            )}
            <div className="button-row">
              <button
                data-dialog-autofocus
                disabled={busy}
                onClick={() => setDeletingProject(null)}
              >
                Cancel
              </button>
              <button
                className="danger-button destructive"
                disabled={busy}
                onClick={() =>
                  act(async () => {
                    setDeleteError("");
                    try {
                      const result = await api<{ cleanup_pending: boolean }>(
                        `/projects/${deletingProject.id}`,
                        "DELETE",
                      );
                      refreshRequest.current?.abort();
                      activeSelection.current = null;
                      setSelected(null);
                      setProject(null);
                      setProjects((previous) =>
                        previous.filter(
                          (item) => item.id !== deletingProject.id,
                        ),
                      );
                      setDeletingProject(null);
                      setNotice(
                        result.cleanup_pending
                          ? "Project deleted. File cleanup will retry automatically."
                          : "Project deleted permanently",
                      );
                    } catch (e) {
                      setDeleteError((e as Error).message);
                      throw e;
                    }
                  }, "")
                }
              >
                {busy ? (
                  <LoaderCircle size={16} className="spin" />
                ) : (
                  <Trash2 size={16} />
                )}
                {busy ? "Deleting…" : "Delete permanently"}
              </button>
            </div>
          </div>
        </Dialog>
      )}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

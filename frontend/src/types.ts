export interface User {
  id?: string;
  username: string;
  role: "admin" | "user";
  csrf: string;
  created_at?: string;
}
export interface Summary {
  counts?: { severity?: Record<string, number> };
  source_freshness?: Record<string, { health?: string }>;
}
export interface Project {
  id: string;
  company: string;
  name: string;
  active_version_id: string | null;
  schedule_enabled: boolean;
  next_run: string | null;
  filename: string | null;
  active_version: string | null;
  latest_state: string | null;
}
export interface Version {
  id: string;
  label: string;
  filename: string;
  created_at: string;
}
export interface ReportJob {
  id: string;
  state: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  scheduled_at: string | null;
  trigger: string;
  version_label: string;
  progress: number;
  total: number | null;
  error: string | null;
  summary: Summary | null;
}
export interface ProjectDetail extends Project {
  versions: Version[];
  jobs: ReportJob[];
}
export interface Worker {
  name: string;
  stale: boolean;
  state: string;
  phase: string | null;
  heartbeat_at: string;
  applied_version: number | null;
  details: {
    phase?: string;
    processed?: number;
    changed?: number;
    report_bytes?: number;
  };
}
export interface Source {
  source: string;
  last_success: string | null;
  error_count: number;
  error_type: string | null;
  next_retry_at: string | null;
}
export interface Status {
  recent_syncs?: {
    id: string;
    source: string;
    status: string;
    started_at: string;
    finished_at: string | null;
    duration_seconds: number | null;
    processed: string | null;
    changed: string | null;
  }[];
  database_bytes: number;
  disk_free_bytes: number;
  disk_total_bytes: number;
  workers: Worker[];
  sources: Source[];
  schedules: { target: string; next_run: string | null }[];
  queue: { state: string; count: number }[];
  jobs: (ReportJob & { company: string; name: string })[];
  server_time: string;
}
export interface AuditEvent {
  id: number;
  created_at: string;
  actor: string;
  action: string;
  details: Record<string, unknown>;
}
export interface Schedule {
  version?: number;
  next_run?: string | null;
  enabled: boolean;
  mode: "interval" | "cron";
  expression: string;
  timezone: string;
  interval_seconds: number | string;
  upcoming?: string[];
}
export interface SyncRun {
  id: string;
  status: string;
  run_type: string;
  started_at: string;
  finished_at: string | null;
  processed: number | null;
  changed: number | null;
  duration_seconds: number | null;
  error_type: string | null;
  legacy: boolean;
}
export interface SyncHistory {
  source: string;
  history: SyncRun[];
  latest: SyncRun | null;
  totals: {
    runs: number;
    succeeded: number;
    failed: number;
    processed: number;
    changed: number;
  };
  offset: number;
  limit: number;
  retention_days: number;
  server_time: string;
  source_state: Source | null;
  worker: { state: string; phase: string | null; stale: boolean } | null;
  schedule: (Schedule & { estimated: boolean; running: boolean }) | null;
}
export interface WorkerSettings {
  settings: Record<string, string>;
  version: number;
  has_api_key: boolean;
}

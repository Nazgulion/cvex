"""Authenticated project workspace, schedules, jobs and telemetry."""
from alembic import op

revision = "0002_workspace"
down_revision = "0001_initial"
branch_labels = depends_on = None


def upgrade():
    op.execute("""
    CREATE TABLE cvex.web_user (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), username text UNIQUE NOT NULL,
      password_hash text NOT NULL, role text NOT NULL CHECK(role IN ('admin','user')),
      created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE cvex.web_session (
      token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES cvex.web_user(id) ON DELETE CASCADE,
      csrf text NOT NULL, expires_at timestamptz NOT NULL);
    CREATE TABLE cvex.login_attempt (address text PRIMARY KEY, attempts integer NOT NULL DEFAULT 0,
      window_start timestamptz NOT NULL DEFAULT now());
    CREATE TABLE cvex.project (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), company text NOT NULL, name text NOT NULL,
      active_version_id uuid, created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE cvex.project_version (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), project_id uuid NOT NULL REFERENCES cvex.project(id),
      sbom_id uuid NOT NULL REFERENCES cvex.sbom_document(id), label text NOT NULL,
      filename text NOT NULL, upload_path text, created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(project_id,sbom_id));
    ALTER TABLE cvex.project ADD FOREIGN KEY(active_version_id) REFERENCES cvex.project_version(id);
    CREATE TABLE cvex.web_schedule (
      target text PRIMARY KEY, enabled boolean NOT NULL DEFAULT false,
      mode text NOT NULL DEFAULT 'cron' CHECK(mode IN ('cron','interval')),
      expression text NOT NULL DEFAULT '0 7 * * *', timezone text NOT NULL DEFAULT 'Europe/Belgrade',
      interval_seconds integer NOT NULL DEFAULT 1800 CHECK(interval_seconds >= 60),
      next_run timestamptz, last_local_occurrence text,
      version integer NOT NULL DEFAULT 1);
    CREATE TABLE cvex.report_job (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), project_id uuid NOT NULL REFERENCES cvex.project(id),
      version_id uuid NOT NULL REFERENCES cvex.project_version(id),
      state text NOT NULL DEFAULT 'queued', trigger text NOT NULL, scheduled_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, finished_at timestamptz,
      heartbeat_at timestamptz, attempts integer NOT NULL DEFAULT 0, available_at timestamptz NOT NULL DEFAULT now(),
      scan_id uuid REFERENCES cvex.scan(id), frozen_payload jsonb, summary jsonb,
      artifacts jsonb, error text, progress integer NOT NULL DEFAULT 0, total integer,
      UNIQUE(project_id,scheduled_at));
    CREATE UNIQUE INDEX one_active_project_job ON cvex.report_job(project_id)
      WHERE state IN ('queued','scanning','exporting');
    CREATE INDEX report_job_queue ON cvex.report_job(available_at) WHERE state='queued';
    CREATE TABLE cvex.report_snapshot (
      job_id uuid PRIMARY KEY REFERENCES cvex.report_job(id), scan_id uuid REFERENCES cvex.scan(id), payload jsonb NOT NULL);
    CREATE TABLE cvex.worker_setting (
      source text PRIMARY KEY CHECK(source IN ('nvd','cve')), settings jsonb NOT NULL DEFAULT '{}',
      encrypted_key text, version integer NOT NULL DEFAULT 1);
    CREATE TABLE cvex.worker_telemetry (
      name text PRIMARY KEY, state text NOT NULL, phase text, heartbeat_at timestamptz NOT NULL DEFAULT now(),
      details jsonb NOT NULL DEFAULT '{}', applied_version integer);
    CREATE TABLE cvex.web_audit (
      id bigserial PRIMARY KEY, actor text NOT NULL, action text NOT NULL,
      details jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now());
    """)


def downgrade():
    op.execute("""
    DROP TABLE cvex.web_audit,cvex.worker_telemetry,cvex.worker_setting,cvex.report_snapshot,cvex.report_job,cvex.web_schedule;
    ALTER TABLE cvex.project DROP CONSTRAINT project_active_version_id_fkey;
    DROP TABLE cvex.project_version,cvex.project,cvex.login_attempt,cvex.web_session,cvex.web_user;
    """)

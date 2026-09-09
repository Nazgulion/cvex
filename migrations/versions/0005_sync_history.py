"""Bounded operational sync history, independent of source evidence provenance."""
from alembic import op

revision = "0005_sync_history"
down_revision = "0004_workspace_indexes"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
      CREATE TABLE cvex.sync_history (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        source text NOT NULL CHECK(source IN ('nvd','cve')),
        status text NOT NULL CHECK(status IN ('running','succeeded','failed','interrupted','deferred')),
        run_type text NOT NULL DEFAULT 'sync',
        started_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
        processed bigint, changed bigint, error_type text,
        legacy boolean NOT NULL DEFAULT false
      );
      CREATE INDEX sync_history_source_recent ON cvex.sync_history(source,started_at DESC,id DESC);
      INSERT INTO cvex.sync_history(id,source,status,run_type,started_at,finished_at,processed,changed,error_type,legacy)
      SELECT id,source,status,run_type,started_at,finished_at,
        (details->>'records_seen')::bigint,(details->>'records_changed')::bigint,
        CASE WHEN split_part(details->>'error',':',1) ~ '^[A-Za-z][A-Za-z0-9_.]*$'
          THEN split_part(details->>'error',':',1) END,true
      FROM cvex.source_run WHERE source IN ('nvd','cve') AND status IN ('succeeded','failed')
        AND started_at >= now()-interval '10 days';
    """)


def downgrade():
    op.execute("DROP TABLE cvex.sync_history")

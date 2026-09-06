"""Durable artifact deletion and a single copy of report snapshots."""
from alembic import op

revision = "0003_review_hardening"
down_revision = "0002_workspace"
branch_labels = depends_on = None


def upgrade():
    op.execute("""
      INSERT INTO cvex.report_snapshot(job_id,scan_id,payload)
        SELECT id,scan_id,frozen_payload FROM cvex.report_job WHERE frozen_payload IS NOT NULL
        ON CONFLICT(job_id) DO NOTHING;
      ALTER TABLE cvex.report_job DROP COLUMN frozen_payload;
      CREATE TABLE cvex.artifact_cleanup (
        path text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
    """)


def downgrade():
    op.execute("""
      ALTER TABLE cvex.report_job ADD COLUMN frozen_payload jsonb;
      UPDATE cvex.report_job j SET frozen_payload=s.payload FROM cvex.report_snapshot s WHERE s.job_id=j.id;
      DROP TABLE cvex.artifact_cleanup;
    """)

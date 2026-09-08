"""Indexes for bounded dashboard, project history and report retention queries."""
from alembic import op

revision = "0004_workspace_indexes"
down_revision = "0003_review_hardening"
branch_labels = depends_on = None


def upgrade():
    op.execute("""
      CREATE INDEX report_job_project_history ON cvex.report_job(project_id,created_at DESC);
      CREATE INDEX report_job_retention ON cvex.report_job(project_id,finished_at DESC,id DESC)
        WHERE state IN ('succeeded','partial');
      CREATE INDEX source_run_recent_sync ON cvex.source_run(started_at DESC)
        WHERE source IN ('nvd','cve');
    """)


def downgrade():
    op.execute("DROP INDEX cvex.source_run_recent_sync,cvex.report_job_retention,cvex.report_job_project_history")

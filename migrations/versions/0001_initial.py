"""CVEX v2 compact baseline for fresh databases.

Revision ID: 0001_initial
Revises:
"""
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
    op.execute("CREATE SCHEMA IF NOT EXISTS cvex")
    op.execute("""
      CREATE TABLE cvex.source_run (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), source text NOT NULL, run_type text NOT NULL,
        status text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
        details jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX ix_source_run_source_started ON cvex.source_run(source, started_at DESC);
      CREATE TABLE cvex.connector_state (
        source text PRIMARY KEY, enabled boolean NOT NULL DEFAULT true, status text NOT NULL DEFAULT 'idle',
        health text NOT NULL DEFAULT 'healthy', last_attempt timestamptz, last_success timestamptz,
        last_error text, error_count integer NOT NULL DEFAULT 0, checkpoint_type text, checkpoint_value text,
        freshness_sla_seconds integer, retry_window_seconds integer, next_retry_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE TABLE cvex.source_payload (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), source text NOT NULL, cve_id text NOT NULL,
        source_modified timestamptz, fetched_at timestamptz NOT NULL DEFAULT now(), sha256 text NOT NULL,
        payload jsonb NOT NULL, run_id uuid REFERENCES cvex.source_run(id), UNIQUE(source, cve_id)
      );
      CREATE INDEX ix_source_payload_modified ON cvex.source_payload(source, source_modified);
      CREATE INDEX ix_source_payload_cve ON cvex.source_payload(cve_id);
      CREATE TABLE cvex.vulnerability (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), cve_id text NOT NULL UNIQUE, published timestamptz,
        modified timestamptz, withdrawn timestamptz, status text NOT NULL DEFAULT 'active', description text,
        description_source text, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE TABLE cvex.vulnerability_severity (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), cve_id text NOT NULL REFERENCES cvex.vulnerability(cve_id) ON DELETE CASCADE,
        metric_type text NOT NULL, ordinal integer NOT NULL DEFAULT 0, score double precision, vector text,
        label text, raw jsonb NOT NULL DEFAULT '{}'::jsonb, UNIQUE(cve_id, metric_type, ordinal)
      );
      CREATE INDEX ix_vulnerability_severity_cve ON cvex.vulnerability_severity(cve_id);
      CREATE TABLE cvex.affected_cpe (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), cve_id text NOT NULL REFERENCES cvex.vulnerability(cve_id) ON DELETE CASCADE,
        cpe text, cpe_criteria text, cpe_part text, cpe_vendor text, cpe_product text, cpe_version text,
        vulnerable boolean, match_criteria_id text, version_start text, version_end text,
        start_inclusive boolean, end_inclusive boolean, raw_range jsonb NOT NULL DEFAULT '{}'::jsonb
      );
      CREATE INDEX ix_affected_cpe_lookup ON cvex.affected_cpe(cpe_vendor, cpe_product, cve_id) WHERE vulnerable IS TRUE;
      CREATE INDEX ix_affected_cpe_cve ON cvex.affected_cpe(cve_id);
      CREATE TABLE cvex.product (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), client_name text NOT NULL, product_name text NOT NULL,
        release_version text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE(client_name, product_name, release_version)
      );
      CREATE TABLE cvex.sbom_document (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), product_id uuid NOT NULL REFERENCES cvex.product(id), format text NOT NULL,
        format_version text, content_sha256 text NOT NULL UNIQUE, name text, document_namespace text, created_by text,
        created_at_source timestamptz, raw_payload jsonb NOT NULL, imported_at timestamptz NOT NULL DEFAULT now(),
        run_id uuid REFERENCES cvex.source_run(id)
      );
      CREATE TABLE cvex.sbom_component (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), sbom_document_id uuid NOT NULL REFERENCES cvex.sbom_document(id) ON DELETE CASCADE,
        source_component_id text NOT NULL, component_kind text NOT NULL, name text NOT NULL, raw_version text,
        normalized_version text, version_status text NOT NULL, version_reason text, supplier text, download_location text,
        created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE(sbom_document_id, source_component_id)
      );
      CREATE INDEX ix_sbom_component_name ON cvex.sbom_component(name);
      CREATE TABLE cvex.component_identity (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), component_id uuid NOT NULL REFERENCES cvex.sbom_component(id) ON DELETE CASCADE,
        identity_type text NOT NULL, identity_value text NOT NULL, UNIQUE(component_id, identity_type, identity_value)
      );
      CREATE INDEX ix_component_identity_value ON cvex.component_identity(identity_type, identity_value);
      CREATE TABLE cvex.component_relationship (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), sbom_document_id uuid NOT NULL REFERENCES cvex.sbom_document(id) ON DELETE CASCADE,
        from_component_id uuid NOT NULL REFERENCES cvex.sbom_component(id) ON DELETE CASCADE,
        to_component_id uuid NOT NULL REFERENCES cvex.sbom_component(id) ON DELETE CASCADE, relationship_type text NOT NULL,
        UNIQUE(sbom_document_id, from_component_id, to_component_id, relationship_type)
      );
      CREATE TABLE cvex.scan (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), sbom_document_id uuid NOT NULL REFERENCES cvex.sbom_document(id),
        run_id uuid REFERENCES cvex.source_run(id), status text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(),
        finished_at timestamptz, source_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
        created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE TABLE cvex.scan_component_result (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), scan_id uuid NOT NULL REFERENCES cvex.scan(id) ON DELETE CASCADE,
        component_id uuid NOT NULL REFERENCES cvex.sbom_component(id), status text NOT NULL, reason_code text NOT NULL,
        reason_message text NOT NULL, warnings jsonb NOT NULL DEFAULT '[]'::jsonb,
        created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(scan_id, component_id)
      );
      CREATE TABLE cvex.vulnerability_finding (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), scan_id uuid NOT NULL REFERENCES cvex.scan(id) ON DELETE CASCADE,
        component_id uuid NOT NULL REFERENCES cvex.sbom_component(id), vulnerability_id uuid NOT NULL REFERENCES cvex.vulnerability(id),
        status text NOT NULL, confidence text NOT NULL, display_severity text, display_score double precision,
        inactive boolean NOT NULL DEFAULT false, matched_at timestamptz NOT NULL DEFAULT now(),
        created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE(scan_id, component_id, vulnerability_id)
      );
      CREATE TABLE cvex.finding_evidence (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), finding_id uuid NOT NULL REFERENCES cvex.vulnerability_finding(id) ON DELETE CASCADE,
        source text NOT NULL, match_type text NOT NULL, matched_identity_type text, matched_identity_value text,
        matched_version text, matched_range jsonb NOT NULL DEFAULT '{}'::jsonb, confidence text NOT NULL, reason text NOT NULL,
        source_payload_id uuid REFERENCES cvex.source_payload(id), warnings jsonb NOT NULL DEFAULT '[]'::jsonb
      );
      CREATE TABLE cvex.report_export (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), scan_id uuid NOT NULL REFERENCES cvex.scan(id),
        run_id uuid REFERENCES cvex.source_run(id), export_type text NOT NULL, path text NOT NULL,
        sha256 text NOT NULL, generated_at timestamptz NOT NULL DEFAULT now()
      )
    """)


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS cvex CASCADE")

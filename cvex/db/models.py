from __future__ import annotations

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


UUID_PK = UUID(as_uuid=True)


class SourceRun(Base):
    __tablename__ = "source_run"
    __table_args__ = {"schema": "cvex"}

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    source: Mapped[str] = mapped_column(Text)
    run_type: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    started_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    finished_at = mapped_column(DateTime(timezone=True), nullable=True)
    details = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    created_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))


class ConnectorState(Base):
    __tablename__ = "connector_state"
    __table_args__ = {"schema": "cvex"}

    source: Mapped[str] = mapped_column(Text, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(Text, default="idle")
    health: Mapped[str] = mapped_column(Text, default="healthy")
    last_attempt = mapped_column(DateTime(timezone=True), nullable=True)
    last_success = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    checkpoint_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    checkpoint_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    freshness_sla_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    retry_window_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    next_retry_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))


class SourcePayload(Base):
    """Latest upstream document for one source/CVE pair."""

    __tablename__ = "source_payload"
    __table_args__ = (UniqueConstraint("source", "cve_id"), {"schema": "cvex"})

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    source: Mapped[str] = mapped_column(Text)
    cve_id: Mapped[str] = mapped_column(Text)
    source_modified = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    sha256: Mapped[str] = mapped_column(Text)
    payload = mapped_column(JSONB)
    run_id = mapped_column(UUID_PK, ForeignKey("cvex.source_run.id"), nullable=True)


class VulnerabilitySeverity(Base):
    __tablename__ = "vulnerability_severity"
    __table_args__ = (UniqueConstraint("cve_id", "metric_type", "ordinal"), {"schema": "cvex"})

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    cve_id: Mapped[str] = mapped_column(Text, ForeignKey("cvex.vulnerability.cve_id", ondelete="CASCADE"))
    metric_type: Mapped[str] = mapped_column(Text)
    ordinal: Mapped[int] = mapped_column(Integer, default=0)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    vector: Mapped[str | None] = mapped_column(Text, nullable=True)
    label: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw = mapped_column(JSONB, server_default=text("'{}'::jsonb"))

    @property
    def severity_type(self):
        return self.metric_type

    @severity_type.setter
    def severity_type(self, value):
        self.metric_type = value


class AffectedCpe(Base):
    __tablename__ = "affected_cpe"
    __table_args__ = {"schema": "cvex"}

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    cve_id: Mapped[str] = mapped_column(Text, ForeignKey("cvex.vulnerability.cve_id", ondelete="CASCADE"))
    cpe: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpe_criteria: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpe_part: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpe_vendor: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpe_product: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpe_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    vulnerable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    match_criteria_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_start: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_end: Mapped[str | None] = mapped_column(Text, nullable=True)
    start_inclusive: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    end_inclusive: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    raw_range = mapped_column(JSONB, server_default=text("'{}'::jsonb"))

    # Non-persistent compatibility attributes for old parser-level callers.
    ecosystem = None
    package_name = None
    introduced = None
    fixed = None
    last_affected = None
    range_type = None


class Vulnerability(Base):
    __tablename__ = "vulnerability"
    __table_args__ = {"schema": "cvex"}

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    cve_id: Mapped[str] = mapped_column(Text, unique=True)
    published = mapped_column(DateTime(timezone=True), nullable=True)
    modified = mapped_column(DateTime(timezone=True), nullable=True)
    withdrawn = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(Text, default="active")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    description_source: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))


    @property
    def primary_identifier(self) -> str:
        """Compatibility for report code; CVE ID is now the canonical identity."""
        return self.cve_id


class Product(Base):
    __tablename__ = "product"
    __table_args__ = (UniqueConstraint("client_name", "product_name", "release_version"), {"schema": "cvex"})

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    client_name: Mapped[str] = mapped_column(Text)
    product_name: Mapped[str] = mapped_column(Text)
    release_version: Mapped[str] = mapped_column(Text)
    created_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))


class SbomDocument(Base):
    __tablename__ = "sbom_document"
    __table_args__ = {"schema": "cvex"}

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    product_id = mapped_column(UUID_PK, ForeignKey("cvex.product.id"))
    format: Mapped[str] = mapped_column(Text)
    format_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_sha256: Mapped[str] = mapped_column(Text, unique=True)
    name: Mapped[str | None] = mapped_column(Text, nullable=True)
    document_namespace: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at_source = mapped_column(DateTime(timezone=True), nullable=True)
    raw_payload = mapped_column(JSONB)
    imported_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    run_id = mapped_column(UUID_PK, ForeignKey("cvex.source_run.id"), nullable=True)


class SbomComponent(Base):
    __tablename__ = "sbom_component"
    __table_args__ = (UniqueConstraint("sbom_document_id", "source_component_id"), {"schema": "cvex"})

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    sbom_document_id = mapped_column(UUID_PK, ForeignKey("cvex.sbom_document.id"))
    source_component_id: Mapped[str] = mapped_column(Text)
    component_kind: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    raw_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_status: Mapped[str] = mapped_column(Text)
    version_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    supplier: Mapped[str | None] = mapped_column(Text, nullable=True)
    download_location: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    identities = relationship("ComponentIdentity", cascade="all, delete-orphan")


class ComponentIdentity(Base):
    __tablename__ = "component_identity"
    __table_args__ = (UniqueConstraint("component_id", "identity_type", "identity_value"), {"schema": "cvex"})

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    component_id = mapped_column(UUID_PK, ForeignKey("cvex.sbom_component.id"))
    identity_type: Mapped[str] = mapped_column(Text)
    identity_value: Mapped[str] = mapped_column(Text)


class ComponentRelationship(Base):
    __tablename__ = "component_relationship"
    __table_args__ = (UniqueConstraint("sbom_document_id", "from_component_id", "to_component_id", "relationship_type"), {"schema": "cvex"})

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    sbom_document_id = mapped_column(UUID_PK, ForeignKey("cvex.sbom_document.id"))
    from_component_id = mapped_column(UUID_PK, ForeignKey("cvex.sbom_component.id"))
    to_component_id = mapped_column(UUID_PK, ForeignKey("cvex.sbom_component.id"))
    relationship_type: Mapped[str] = mapped_column(Text)


class Scan(Base):
    __tablename__ = "scan"
    __table_args__ = {"schema": "cvex"}

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    sbom_document_id = mapped_column(UUID_PK, ForeignKey("cvex.sbom_document.id"))
    run_id = mapped_column(UUID_PK, ForeignKey("cvex.source_run.id"), nullable=True)
    status: Mapped[str] = mapped_column(Text)
    started_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    finished_at = mapped_column(DateTime(timezone=True), nullable=True)
    source_snapshot = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    created_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))


class ScanComponentResult(Base):
    __tablename__ = "scan_component_result"
    __table_args__ = (UniqueConstraint("scan_id", "component_id"), {"schema": "cvex"})

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    scan_id = mapped_column(UUID_PK, ForeignKey("cvex.scan.id"))
    component_id = mapped_column(UUID_PK, ForeignKey("cvex.sbom_component.id"))
    status: Mapped[str] = mapped_column(Text)
    reason_code: Mapped[str] = mapped_column(Text)
    reason_message: Mapped[str] = mapped_column(Text)
    warnings = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    created_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_finding"
    __table_args__ = (UniqueConstraint("scan_id", "component_id", "vulnerability_id"), {"schema": "cvex"})

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    scan_id = mapped_column(UUID_PK, ForeignKey("cvex.scan.id"))
    component_id = mapped_column(UUID_PK, ForeignKey("cvex.sbom_component.id"))
    vulnerability_id = mapped_column(UUID_PK, ForeignKey("cvex.vulnerability.id"))
    status: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(Text)
    display_severity: Mapped[str | None] = mapped_column(Text, nullable=True)
    display_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    inactive: Mapped[bool] = mapped_column(Boolean, default=False)
    matched_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    created_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    __table_args__ = {"schema": "cvex"}

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    finding_id = mapped_column(UUID_PK, ForeignKey("cvex.vulnerability_finding.id"))
    source: Mapped[str] = mapped_column(Text)
    match_type: Mapped[str] = mapped_column(Text)
    matched_identity_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched_identity_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched_range = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    confidence: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    source_payload_id = mapped_column(UUID_PK, ForeignKey("cvex.source_payload.id"), nullable=True)
    warnings = mapped_column(JSONB, server_default=text("'[]'::jsonb"))


class ReportExport(Base):
    __tablename__ = "report_export"
    __table_args__ = {"schema": "cvex"}

    id: Mapped[str] = mapped_column(UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    scan_id = mapped_column(UUID_PK, ForeignKey("cvex.scan.id"))
    run_id = mapped_column(UUID_PK, ForeignKey("cvex.source_run.id"), nullable=True)
    export_type: Mapped[str] = mapped_column(Text)
    path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(Text)
    generated_at = mapped_column(DateTime(timezone=True), server_default=text("now()"))


# Source-level compatibility types for callers that only use the parser helpers.
# They are deliberately not mapped and create no v1 tables.
class SourceVulnerability:
    def __init__(self, source: str, primary_id: str, status: str = "active", description: str | None = None, **values):
        self.source = source
        self.primary_id = primary_id
        self.status = status
        self.description = description
        self.source_record_id = values.get("source_record_id")
        self.published = values.get("published")
        self.modified = values.get("modified")
        self.withdrawn = values.get("withdrawn")


# Old class names remain import-compatible without retaining old tables.
SourceAffectedComponent = AffectedCpe
SourceSeverity = VulnerabilitySeverity

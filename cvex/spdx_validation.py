"""Validate the SPDX fields consumed by our importer before creating DB rows."""
from pydantic import BaseModel, ConfigDict, Field


class SpdxFields(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)


class ExternalReference(SpdxFields):
    referenceCategory: str
    referenceType: str = Field(min_length=1)
    referenceLocator: str = Field(min_length=1)


class Package(SpdxFields):
    SPDXID: str = Field(min_length=1)
    name: str = Field(min_length=1)
    versionInfo: str | None = None
    supplier: str | None = None
    downloadLocation: str | None = None
    externalRefs: list[ExternalReference] | None = None


class CreationInfo(SpdxFields):
    creators: list[str] = Field(default_factory=list)
    created: str | None = None


class Relationship(SpdxFields):
    spdxElementId: str
    relatedSpdxElement: str
    relationshipType: str


class SpdxDocument(SpdxFields):
    spdxVersion: str = Field(pattern=r"^SPDX-")
    name: str | None = None
    documentNamespace: str | None = None
    creationInfo: CreationInfo | None = None
    packages: list[Package] = Field(min_length=1)
    relationships: list[Relationship] = Field(default_factory=list)


def validate_spdx(payload):
    document = SpdxDocument.model_validate(payload)
    identifiers = [package.SPDXID for package in document.packages]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("Each package must have a unique SPDXID")
    if document.creationInfo and document.creationInfo.created:
        from cvex.util import parse_dt
        parse_dt(document.creationInfo.created)

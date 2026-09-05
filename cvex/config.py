from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    url: str


class LoggingConfig(BaseModel):
    level: str = "DEBUG"
    format: str = "plain"


class HistoryConfig(BaseModel):
    lookback_years: int = 10
    start_date: Optional[str] = None


class SyncConfig(BaseModel):
    incremental_overlap: str = "15m"


class PathsConfig(BaseModel):
    cache_root: str = "/var/lib/cvex/cache"
    status_root: str = "/var/lib/cvex/status"
    report_root: str = "reports"


class ProcessingConfig(BaseModel):
    source_chunk_size: int = 1_000


class DiskConfig(BaseModel):
    warn_free_percent_below: int = 15
    warn_free_bytes_below: int = 10_737_418_240
    critical_free_percent_below: int = 5
    critical_free_bytes_below: int = 2_147_483_648


class NetworkConfig(BaseModel):
    ca_bundle: Optional[str] = None


class SourceConfig(BaseModel):
    enabled: bool = True
    sync_interval: str
    freshness_sla: str
    retry_window: str
    initial_retry_delay: str
    max_retry_delay: str
    request_timeout: str
    cache_dir: str
    git_url: Optional[str] = None
    git_ref: str = "main"
    api_url: Optional[str] = None
    feed_base_url: Optional[str] = None
    dump_base_url: Optional[str] = None
    no_key_request_pause: Optional[str] = None
    api_key_request_pause: Optional[str] = None
    api_key: Optional[str] = None
    ecosystems: List[str] = Field(default_factory=list)


class IdentityAliasConfig(BaseModel):
    cpe_vendor: str
    cpe_product: str
    cpe_part: str = "a"


class VersionOverrideConfig(BaseModel):
    version: str
    source: str
    component_name: Optional[str] = None
    source_component_id: Optional[str] = None
    raw_version: Optional[str] = None


class CvexConfig(BaseModel):
    database: DatabaseConfig
    logging: LoggingConfig
    history: HistoryConfig
    sync: SyncConfig
    paths: PathsConfig
    processing: ProcessingConfig
    disk: DiskConfig
    network: NetworkConfig
    attribution: Dict[str, str]
    sources: Dict[str, SourceConfig]
    identity_aliases: Dict[str, IdentityAliasConfig] = Field(default_factory=dict)
    version_overrides: List[VersionOverrideConfig] = Field(default_factory=list)
    retention: Dict[str, str] = Field(default_factory=dict)
    workers: Dict[str, int] = Field(default_factory=dict)


def load_config(path: str | Path = "config/cvex.yaml") -> CvexConfig:
    config_path = Path(path)
    with config_path.open("r", encoding="utf-8") as fh:
        data: Dict[str, Any] = yaml.safe_load(fh) or {}

    if os.environ.get("CVEX_DATABASE_URL"):
        data.setdefault("database", {})["url"] = os.environ["CVEX_DATABASE_URL"]
    if os.environ.get("NVD_API_KEY"):
        data.setdefault("sources", {}).setdefault("nvd", {})["api_key"] = os.environ["NVD_API_KEY"]

    return CvexConfig.model_validate(data)

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AttackType(str, Enum):
    flooding = "flooding"
    replay = "replay"
    malformed_message = "malformed_message"
    oversized_payload = "oversized_payload"
    injection_simulated = "injection_simulated"
    normal = "normal"
    unknown = "unknown"


class Vulnerability(BaseModel):
    id: str
    title: str = ""
    description: str = ""
    source: str = "manual"
    cvss: float | None = None
    severity: str = "unknown"
    cwe: str = ""
    published_at: str = ""
    affected_product: str = ""

    @field_validator("cvss", mode="before")
    @classmethod
    def parse_cvss(cls, value):
        try:
            return min(10.0, max(0.0, float(value))) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None


class ThreatAnalysis(BaseModel):
    protocol: str = "unknown"
    likely_attack_type: AttackType = AttackType.unknown
    preconditions: str = ""
    expected_network_behavior: str = ""
    dataset_label: str = "unknown"
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    safety_notes: str = ""
    source: str = "rules"


class Scenario(BaseModel):
    scenario_id: str
    protocol: str
    attack_type: AttackType
    duration_seconds: int = Field(30, gt=0, le=3600)
    normal_traffic_command: str = ""
    attack_command: str = ""
    capture_interface: str = "any"
    output_pcap: str
    label: str
    notes: str = ""


class DatasetMeta(BaseModel):
    name: str
    source_file: str
    rows: int
    label_column: str
    labels: list[str]
    created_at: str
    notes: str = ""


class RunRecord(BaseModel):
    run_id: str
    scenario_id: str
    vuln_id: str = ""
    started_at: str
    status: Literal["created", "dry-run", "running", "done", "failed"] = "created"
    log_path: str = ""
    pcap_path: str = ""
    effect_verdict: Literal["valid", "invalid", "inconclusive", "not_validated"] = "not_validated"
    responsive_before: Literal["yes", "no", "unknown", ""] = ""
    responsive_after: Literal["yes", "no", "unknown", ""] = ""
    anomalies: str = ""
    llm_model: str = ""
    llm_seed: str = ""


class ProbeResult(BaseModel):
    responsive: bool = False
    detail: str = ""
    latency_ms: float | None = None
    source: Literal["probe", "plugin", "tcp", "udp"] = "probe"


class EffectReport(BaseModel):
    verdict: Literal["valid", "invalid", "inconclusive"] = "inconclusive"
    responsive_before: bool | None = None
    responsive_after: bool | None = None
    packets_out: int = 0
    packets_in: int = 0
    anomalies: list[str] = []
    notes: str = ""


"""Pydantic v2 data models for VulnForge AI."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class AttackType(str, Enum):
    """Supported laboratory attack categories."""

    FLOODING = "flooding"
    REPLAY = "replay"
    MALFORMED_MESSAGE = "malformed_message"
    OVERSIZED_PAYLOAD = "oversized_payload"
    INJECTION_SIMULATED = "injection_simulated"
    NORMAL = "normal"
    UNKNOWN = "unknown"


class Vulnerability(BaseModel):
    """Canonical vulnerability record imported from JSON/CSV."""

    id: str
    title: str = ""
    description: str = ""
    source: str = "manual"
    cvss: float | None = None
    severity: str = "unknown"
    cwe: str = ""
    published_at: str = ""
    affected_product: str = ""

    @field_validator("cvss")
    @classmethod
    def _clamp_cvss(cls, value: float | None) -> float | None:
        if value is None:
            return None
        return max(0.0, min(10.0, float(value)))


class ThreatAnalysis(BaseModel):
    """Structured output of the threat analyzer (LLM or rule-based)."""

    protocol: str = "unknown"
    likely_attack_type: AttackType = AttackType.UNKNOWN
    preconditions: str = ""
    expected_network_behavior: str = ""
    dataset_label: str = "unknown"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    safety_notes: str = ""
    source: str = "rules"  # rules | openrouter | local


class Scenario(BaseModel):
    """Controlled laboratory scenario serialized as YAML."""

    scenario_id: str
    protocol: str
    attack_type: AttackType
    duration_seconds: int = Field(default=30, gt=0, le=3600)
    normal_traffic_command: str = ""
    attack_command: str = ""
    capture_interface: str = "any"
    output_pcap: str
    label: str
    notes: str = ""


class DatasetMeta(BaseModel):
    """Metadata sidecar for a generated dataset."""

    name: str
    source_file: str
    rows: int
    label_column: str
    labels: list[str]
    created_at: str
    notes: str = ""


class RunRecord(BaseModel):
    """Persistence record for one scenario execution."""

    run_id: str
    scenario_id: str
    vuln_id: str = ""
    started_at: str
    status: str = "created"  # created | dry-run | running | done | failed
    log_path: str = ""
    pcap_path: str = ""
    effect_verdict: str = "not_validated"  # valid | invalid | inconclusive | not_validated
    responsive_before: str = ""  # yes | no | unknown
    responsive_after: str = ""   # yes | no | unknown
    anomalies: str = ""
    llm_model: str = ""
    llm_seed: str = ""


class ProbeResult(BaseModel):
    """Result of a health probe against a lab target."""

    responsive: bool = False
    detail: str = ""
    latency_ms: float | None = None
    source: str = "probe"  # probe | plugin | tcp | udp


class EffectReport(BaseModel):
    """Verdict about whether an attack produced a real effect."""

    verdict: str = "inconclusive"  # valid | invalid | inconclusive
    responsive_before: bool | None = None
    responsive_after: bool | None = None
    packets_out: int = 0
    packets_in: int = 0
    anomalies: list[str] = Field(default_factory=list)
    notes: str = ""

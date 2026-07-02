"""Optional read-only FastAPI application."""

from __future__ import annotations

try:
    from fastapi import FastAPI
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "FastAPI nao instalado. Instale a extra 'api': pip install 'vulnforge-ai[api]'"
    ) from exc

from .llm.analyzer import analyze as analyze_text
from .models import ThreatAnalysis
from .scenarios.generator import generate as generate_scenario

app = FastAPI(title="VulnForge AI")


class AnalyzeRequest(BaseModel):
    text: str
    protocol: str | None = None


class GenerateScenarioRequest(BaseModel):
    text: str
    protocol: str | None = None
    target: str = "127.0.0.1"
    interface: str = "any"
    duration: int = Field(default=30, gt=0, le=3600)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    result = analyze_text(req.text, protocol_hint=req.protocol)
    return result.model_dump(mode="json")


@app.post("/generate-scenario")
def generate_scenario_endpoint(req: GenerateScenarioRequest) -> dict:
    analysis = analyze_text(req.text, protocol_hint=req.protocol)
    scenario = generate_scenario(
        analysis,
        target=req.target,
        interface=req.interface,
        duration=req.duration,
        prefer_container=True,
    )
    return scenario.model_dump(mode="json")

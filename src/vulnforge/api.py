"""API FastAPI opcional (nao roda por padrao).

Suba com: `uvicorn vulnforge.api:app --reload` (requer extra `api`).
Expoe analyze e generate-scenario; nao executa ataques.
"""

from __future__ import annotations

from pydantic import BaseModel

try:
    from fastapi import FastAPI
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "FastAPI nao instalado. Instale o extra: pip install 'vulnforge-ai[api]'"
    ) from exc

from .llm import analyzer
from .models import ThreatAnalysis
from .scenarios import generator

app = FastAPI(title="VulnForge AI", version="0.1.0")


class AnalyzeRequest(BaseModel):
    text: str
    protocol: str | None = None


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=ThreatAnalysis)
def analyze(req: AnalyzeRequest) -> ThreatAnalysis:
    return analyzer.analyze(req.text, protocol=req.protocol)


@app.post("/generate-scenario")
def generate_scenario(req: AnalyzeRequest) -> dict:
    analysis = analyzer.analyze(req.text, protocol=req.protocol)
    scenario = generator.generate(analysis)
    return scenario.model_dump(mode="json")

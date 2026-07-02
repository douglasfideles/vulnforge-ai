try:
    from fastapi import FastAPI
    from pydantic import BaseModel
except ImportError as exc:
    raise RuntimeError("FastAPI support requires: pip install 'vulnforge-ai[api]'") from exc

from vulnforge.llm.analyzer import analyze
from vulnforge.scenarios.generator import generate_scenario

app = FastAPI(title="VulnForge AI")


class AnalysisRequest(BaseModel):
    text: str
    protocol: str = ""


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_endpoint(request: AnalysisRequest):
    return analyze(request.text, request.protocol)


@app.post("/generate-scenario")
async def scenario_endpoint(request: AnalysisRequest):
    return generate_scenario(analyze(request.text, request.protocol)).model_dump(mode="json")

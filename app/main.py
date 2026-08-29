from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    provider_base_url: HttpUrl | None = None
    provider_api_key: str | None = None
    provider_api_key_header: str = "Authorization"
    provider_model: str = "local-model"
    provider_timeout_seconds: float = 30.0
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINELMESH_", extra="ignore")


settings = Settings()
app = FastAPI(
    title="SentinelMesh",
    version="0.2.0",
    description="A provider-optional defensive security report generator and triage copilot.",
)


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_SCORE = {
    Severity.info: 10,
    Severity.low: 25,
    Severity.medium: 50,
    Severity.high: 75,
    Severity.critical: 95,
}


class Finding(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=10_000)
    severity: Severity
    asset: str = Field(default="unknown", max_length=500)
    source: str = Field(default="agent", max_length=200)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    references: list[HttpUrl] = Field(default_factory=list, max_length=20)
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingBatch(BaseModel):
    findings: list[Finding] = Field(min_length=1, max_length=1_000)


class CopilotRequest(BaseModel):
    findings: list[Finding] = Field(min_length=1, max_length=1_000)
    use_ai: bool = False
    audience: str = Field(default="security engineering", max_length=100)


def summarize(findings: list[Finding]) -> dict[str, Any]:
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    score = round(sum(SEVERITY_SCORE[f.severity] for f in findings) / len(findings))
    rating = (
        "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 35 else "low"
    )
    return {"score": score, "rating": rating, "counts": counts}


def provider_headers() -> dict[str, str]:
    if not settings.provider_api_key:
        return {}
    value = settings.provider_api_key
    if (
        settings.provider_api_key_header.lower() == "authorization"
        and not value.lower().startswith("bearer ")
    ):
        value = f"Bearer {value}"
    return {settings.provider_api_key_header: value}


def deterministic_triage(findings: list[Finding]) -> dict[str, Any]:
    ordered = sorted(findings, key=lambda item: SEVERITY_SCORE[item.severity], reverse=True)
    priorities = []
    for index, finding in enumerate(ordered, start=1):
        action = {
            Severity.critical: "Contain the affected asset and begin incident response validation.",
            Severity.high: "Assign an owner and remediate or apply compensating controls urgently.",
            Severity.medium: "Schedule remediation, verify exposure, and track to completion.",
            Severity.low: "Backlog for routine hardening and confirm the finding is understood.",
            Severity.info: "Record as informational context and review for related exposure.",
        }[finding.severity]
        priorities.append(
            {
                "priority": index,
                "title": finding.title,
                "severity": finding.severity,
                "asset": finding.asset,
                "recommended_action": action,
            }
        )
    summary = summarize(findings)
    report = (
        f"Security triage report: {len(findings)} finding(s), "
        f"overall risk {summary['rating']} ({summary['score']}/100)."
    )
    return {"mode": "deterministic", "report": report, "summary": summary, "priorities": priorities}


async def ai_triage(findings: list[Finding], audience: str) -> dict[str, Any]:
    if not settings.provider_base_url or not settings.provider_api_key:
        return deterministic_triage(findings)
    prompt = (
        "You are a defensive security triage assistant. Analyze only the supplied findings. "
        "Do not invent evidence, credentials, exploits, or remediation results. Return concise "
        "Markdown with: executive summary, prioritized findings, evidence gaps, "
        "and safe next steps.\n\n"
        f"Audience: {audience}\nFindings:\n"
        + "\n".join(f.model_dump_json() for f in findings)
    )
    payload = {
        "model": settings.provider_model,
        "messages": [
            {"role": "system", "content": "Produce an authorized defensive security report."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
    }
    try:
        async with httpx.AsyncClient(timeout=settings.provider_timeout_seconds) as client:
            response = await client.post(
                str(settings.provider_base_url), json=payload, headers=provider_headers()
            )
            response.raise_for_status()
            data = response.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content")
        if not content:
            raise ValueError("Provider response did not contain chat content")
        return {"mode": "ai", "report": content, "summary": summarize(findings)}
    except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError):
        return {
            **deterministic_triage(findings),
            "mode": "deterministic_fallback",
            "provider_error": (
                "The configured provider was unavailable or returned an invalid response."
            ),
        }


@app.get("/health")
def health() -> dict[str, str | bool]:
    configured = bool(settings.provider_base_url and settings.provider_api_key)
    return {"status": "ok", "provider_configured": configured}


@app.post("/v1/findings/normalize")
def normalize(batch: FindingBatch) -> dict[str, Any]:
    return {
        "findings": [finding.model_dump(mode="json") for finding in batch.findings],
        "summary": summarize(batch.findings),
    }


@app.post("/v1/copilot/triage")
async def triage(request: CopilotRequest) -> dict[str, Any]:
    if request.use_ai:
        return await ai_triage(request.findings, request.audience)
    return deterministic_triage(request.findings)


@app.post("/v1/provider/check")
async def provider_check() -> dict[str, Any]:
    if not settings.provider_base_url:
        raise HTTPException(status_code=400, detail="Set SENTINELMESH_PROVIDER_BASE_URL first")
    try:
        async with httpx.AsyncClient(timeout=settings.provider_timeout_seconds) as client:
            response = await client.get(str(settings.provider_base_url), headers=provider_headers())
        return {"reachable": response.is_success, "status_code": response.status_code}
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Provider request failed") from exc

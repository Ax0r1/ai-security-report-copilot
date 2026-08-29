from fastapi.testclient import TestClient

from app.main import app, settings

client = TestClient(app)


def test_health_is_available():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_normalize_returns_risk_summary():
    response = client.post(
        "/v1/findings/normalize",
        json={
            "findings": [
                {
                    "title": "Exposed debug endpoint",
                    "description": "A development endpoint is reachable.",
                    "severity": "high",
                    "asset": "api.example.test",
                    "source": "demo-agent",
                },
                {
                    "title": "Missing security header",
                    "severity": "low",
                    "asset": "web.example.test",
                },
            ]
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["score"] == 50
    assert payload["summary"]["counts"]["high"] == 1
    assert len(payload["findings"]) == 2


def test_triage_works_without_any_api():
    response = client.post(
        "/v1/copilot/triage",
        json={
            "findings": [
                {
                    "title": "Critical secret exposure",
                    "severity": "critical",
                    "asset": "repo.example.test",
                },
                {
                    "title": "Informational banner",
                    "severity": "info",
                    "asset": "web.example.test",
                },
            ],
            "use_ai": False,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["mode"] == "deterministic"
    assert payload["priorities"][0]["severity"] == "critical"
    assert payload["summary"]["rating"] == "medium"


def test_provider_check_requires_configuration():
    original = settings.provider_base_url
    settings.provider_base_url = None
    try:
        response = client.post("/v1/provider/check")
        assert response.status_code == 400
    finally:
        settings.provider_base_url = original

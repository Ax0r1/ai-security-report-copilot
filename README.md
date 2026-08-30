# AI Security Report Generator / Triage Copilot

[![CI](https://github.com/Ax0r1/ai-security-report-copilot/actions/workflows/ci.yml/badge.svg)](https://github.com/Ax0r1/ai-security-report-copilot/actions/workflows/ci.yml) [![Latest release](https://img.shields.io/github/v/release/Ax0r1/ai-security-report-copilot)](https://github.com/Ax0r1/ai-security-report-copilot/releases) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

AI Security Report Generator / Triage Copilot is a provider-agnostic defensive security gateway and **AI Security Report Generator / Triage Copilot** for connecting security agents to an API owned and configured by each operator. It normalizes findings, produces a transparent risk summary, prioritizes remediation, and generates an executive-ready report without requiring users to share credentials with the project maintainer.

> AI Security Report Generator / Triage Copilot is designed for authorized defensive security operations. Do not use it to access systems, data, or networks without explicit permission.

## Features

| Capability | Description |
| --- | --- |
| Bring-your-own API | Each deployment supplies its own provider URL and API key through environment variables. |
| Finding normalization | Converts agent findings into a consistent schema with severity, asset, source, references, and metadata. |
| Explainable risk score | Calculates a simple average severity score and rating without opaque decisions. |
| Provider health check | Verifies that the configured provider endpoint is reachable. |
| AI report generation | Uses an optional OpenAI-compatible provider to draft a concise defensive report. |
| No-API mode | The triage copilot works with deterministic prioritization even when no model is configured. |
| Local model support | Point the provider URL at a self-hosted OpenAI-compatible endpoint such as Ollama. |
| Secure defaults | Secrets are never committed, returned in API responses, or written to logs by the application. |
| Easy deployment | Runs locally or in Docker and includes automated tests and CI. |

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/sentinelmesh.git
cd sentinelmesh
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
uvicorn app.main:app --reload
```

The service is available at `http://127.0.0.1:8000`. Interactive API documentation is available at `/docs`.

No API key is required for the deterministic triage mode. AI report generation is optional and uses the deployment operator's own provider configuration.

## Configure your own provider

Copy the example environment file and edit it locally:

```bash
cp .env.example .env
```

Set `SENTINELMESH_PROVIDER_BASE_URL` to the endpoint that your organization controls and set `SENTINELMESH_PROVIDER_API_KEY` to that provider's key. The `.env` file is ignored by Git and must never be committed. The default authentication format is `Authorization: Bearer <key>`; use `SENTINELMESH_PROVIDER_API_KEY_HEADER` for a provider-specific header.

AI Security Report Generator / Triage Copilot does not contain a shared hosted key and does not transmit credentials to the project maintainer.

## API examples

Normalize agent findings:

```bash
curl -X POST http://127.0.0.1:8000/v1/findings/normalize \
  -H 'Content-Type: application/json' \
  -d '{
    "findings": [{
      "title": "Exposed debug endpoint",
      "description": "A development endpoint is reachable.",
      "severity": "high",
      "asset": "api.example.test",
      "source": "demo-agent"
    }]
  }'
```

Generate a deterministic triage report without any AI API:

```bash
curl -X POST http://127.0.0.1:8000/v1/copilot/triage \\
  -H 'Content-Type: application/json' \\
  -d '{
    "use_ai": false,
    "findings": [{
      "title": "Exposed debug endpoint",
      "severity": "high",
      "asset": "api.example.test"
    }]
  }'
```

To use AI, set `use_ai` to `true` and configure an OpenAI-compatible chat endpoint. The service sends only the supplied findings to the provider and returns a safe fallback if the provider is unavailable.

Check the configured provider:

```bash
curl -X POST http://127.0.0.1:8000/v1/provider/check
```

## Docker

```bash
docker build -t sentinelmesh .
docker run --rm -p 8000:8000 --env-file .env sentinelmesh
```

## Development

```bash
pytest
ruff check .
```

The project intentionally starts with a small, auditable core. Future adapters can be added behind the provider boundary for SIEM, ticketing, notification, and agent platforms without changing the normalized finding contract.

## Security policy

Please do not disclose vulnerabilities in public issues. Use the private reporting process described in [SECURITY.md](SECURITY.md). Never include live credentials, personal data, or unauthorized target information in bug reports or examples.

## License

MIT. See [LICENSE](LICENSE).

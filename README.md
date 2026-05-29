# 🛡️ SecureQA Orchestrator

> Security testing orchestrator for QA engineers — API, UI, and AI-fuzzing in one workspace.

## Status

✅ **Phase 0: Shared Foundation — Complete**
✅ **Phase 1A: Spec Ingestion (OpenAPI + Postman) — Complete**
🚀 **Phase 1B: Test Generators — Next**

## What is this?

SecureQA Orchestrator is a desktop security testing tool built for QA engineers who want to add security validation to their existing workflows. It runs locally via Streamlit and integrates with ClickUp for ticket creation.

## Roadmap

- [x] **Phase 0:** Shared foundation (skeleton, LLM client, safety guard, storage, logging)
- [x] **Phase 1A:** Spec Ingestion — OpenAPI 3.0/3.1 + Postman v2.1 parsers
- [ ] **Phase 1B:** Test Generators — OWASP API Top 10 test generation
- [ ] **Phase 1C:** Execution + Classification — httpx runner + hybrid classifier
- [ ] **Phase 1D:** UI + Exporters — Streamlit tab + real exporters
- [ ] **Phase 2:** UI Security & Session Agent — Playwright-based web UI security checks
- [ ] **Phase 3:** AI Fuzzing & Input Agent — LLM-driven payload generation + classification

## Tech Stack

- **Python** 3.11+
- **Streamlit** for UI
- **Google Gemini 2.5 Flash Lite** for AI features
- **Pydantic v2** for data validation
- **SQLAlchemy 2.0** + SQLite for scan history
- **Loguru** for structured logging
- **Tenacity** for resilient API calls
- **pytest** for testing

## Setup

```bash
# 1. Clone
git clone https://github.com/Yusuf-Hridoy/secureqa-orchestrator.git
cd secureqa-orchestrator

# 2. Virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements-dev.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — add your GEMINI_API_KEY

# 5. Run
streamlit run app.py
```

## Safety First

SecureQA Orchestrator includes a built-in **production block**. It refuses to scan any URL that matches production patterns (e.g., `www.*`, `*production*`, `*.live`). You can configure the allowlist in `config/target_allowlist.json`.

Every scan attempt — allowed or blocked — is logged to an audit trail in the local SQLite DB.

## Usage (Phase 1A — Spec Parsing)

```python
from core.api_security import parse_spec

# Parse from file
with open("api-spec.json", "rb") as f:
    spec = parse_spec(f.read())

print(f"{spec.name}: {spec.endpoint_count()} endpoints")
for endpoint in spec.endpoints:
    print(f"  {endpoint.method.value} {endpoint.path}")
```

Supports:
- OpenAPI 3.0 (JSON / YAML)
- OpenAPI 3.1 (JSON / YAML)
- Postman Collection v2.1 (JSON)

## Development

```bash
# Run tests
pytest

# With coverage
pytest --cov=core --cov-report=term-missing

# API security tests only
pytest tests/api_security/ --cov=core/api_security --cov-report=term-missing

# Lint
ruff check .
ruff format .
```

## Architecture

```
secureqa-orchestrator/
├── app.py              # Streamlit entry point
├── core/               # Business logic (FastAPI-portable, no Streamlit imports)
├── tabs/               # Streamlit UI (thin wrappers around core/)
├── config/             # Settings + allowlist
├── prompts/            # LLM prompt templates (Phase 1+)
├── tests/              # pytest test suite
└── data/               # Runtime data (DB, logs — gitignored)
```

The `core/` package is intentionally Streamlit-free so SecureQA Orchestrator can graduate to FastAPI + custom frontend when needed.

## License

MIT — see [LICENSE](LICENSE)

## Author

[Md Yusuf Ahmed](https://github.com/Yusuf-Hridoy) — QA Automation Engineer

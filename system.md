# SecureQA Orchestrator — System Documentation

> Complete technical reference for the SecureQA Orchestrator codebase.  
> Covers architecture, module responsibilities, data flows, build steps, and extension points.

---

## 1. Project Overview

**SecureQA Orchestrator** is a security testing tool for QA engineers. It provides three security testing modules (API, UI, AI fuzzing) in a single workspace, backed by an LLM (Google Gemini) for intelligent test generation and analysis.

- **License:** MIT
- **Python:** 3.11+
- **UI:** Streamlit (Phase 0), designed for FastAPI portability
- **LLM:** Google Gemini 2.5 Flash Lite
- **Database:** SQLite via SQLAlchemy 2.0

---

## 2. Architecture Principles

### 2.1 FastAPI-Portable Core

The most important architectural constraint: **`core/` must remain free of Streamlit imports.**

| Rule | Rationale |
|------|-----------|
| No `import streamlit` in `core/`, `config/`, `tests/` | Ensures business logic can be lifted into a FastAPI backend later |
| `core/` modules return Pydantic models, never UI widgets | UI-agnostic data contracts |
| Long-running ops yield `ScanProgress` generators | Callers (Streamlit tabs or API endpoints) decide how to render progress |
| Business state goes through `core/storage.py`, not `st.session_state` | Backend-ready state management |
| File handling uses `bytes` or file-like objects | Decoupled from `st.file_uploader` |

### 2.2 Layered Architecture

```
┌─────────────────────────────────────────┐
│  app.py          (Streamlit entrypoint) │
│  tabs/           (UI-only thin wrappers) │
├─────────────────────────────────────────┤
│  core/           (Business logic)        │
│  ├─ models.py    (Pydantic schemas)      │
│  ├─ llm_client.py(Gemini client)         │
│  ├─ safety.py    (Target validation)     │
│  ├─ storage.py   (SQLite persistence)    │
│  ├─ logging_config.py (Loguru setup)     │
│  └─ exporters/   (Report generators)     │
├─────────────────────────────────────────┤
│  config/         (Settings + allowlist)  │
└─────────────────────────────────────────┘
```

---

## 3. Directory Structure

```
secureqa-orchestrator/
├── app.py                      # Streamlit entry point (ONLY streamlit imports here)
├── pyproject.toml              # Tool configs: ruff, pytest, coverage, mypy
├── requirements.txt            # Runtime dependencies (pinned)
├── requirements-dev.txt        # Dev dependencies (+ runtime via -r)
├── .env.example                # Template for environment variables
├── .gitignore                  # Python, IDE, env, build, OS ignores
├── LICENSE                     # MIT License
├── README.md                   # Human-facing project documentation
├── system.md                   # This file
│
├── config/
│   ├── __init__.py
│   ├── settings.py             # pydantic-settings: env var → typed Settings singleton
│   ├── app_config.yaml         # UI defaults, feature flags, scan defaults
│   └── target_allowlist.json   # Glob patterns for allowed/blocked targets
│
├── core/                       # NO streamlit imports allowed
│   ├── __init__.py
│   ├── models.py               # Pydantic v2 models: Finding, ScanResult, SafetyResult, etc.
│   ├── llm_client.py           # GeminiClient: text gen, structured output, retry
│   ├── safety.py               # SafetyGuard: allowlist, blocklist, prod heuristics
│   ├── storage.py              # SQLAlchemy 2.0: ScanRecord, AuditRecord, CRUD ops
│   ├── logging_config.py       # Loguru: console + rotating file sinks
│   └── exporters/
│       ├── __init__.py
│       ├── base.py             # Exporter ABC
│       ├── markdown_exporter.py# Stub → Phase 1
│       ├── csv_exporter.py     # Stub → Phase 1
│       └── clickup_exporter.py # Stub → Phase 1
│
├── tabs/                       # Streamlit UI only
│   ├── __init__.py
│   ├── api_security.py         # Phase 1 placeholder
│   ├── ui_security.py          # Phase 2 placeholder
│   └── ai_fuzzing.py           # Phase 3 placeholder
│
├── prompts/                    # LLM prompt templates (Phase 1+)
│   └── .gitkeep
│
├── data/                       # Runtime data (gitignored)
│   └── .gitkeep
│
└── tests/                      # pytest test suite
    ├── __init__.py
    ├── conftest.py             # Shared fixtures: in-memory DB, sample data, Gemini mocks
    ├── test_models.py          # Pydantic model tests
    ├── test_safety.py          # SafetyGuard tests
    ├── test_storage.py         # SQLite storage tests
    ├── test_llm_client.py      # GeminiClient (mocked) tests
    └── test_exporters.py       # Exporter stub tests
```

---

## 4. Module Deep Dive

### 4.1 `config/settings.py`

**Purpose:** Centralized, type-safe configuration loaded from environment variables (`.env`) via `pydantic-settings`.

**Key features:**
- `SecretStr` for API keys (masks values in logs)
- Case-insensitive env var matching
- Singleton instance `settings = Settings()` for import-time convenience
- `get_settings()` factory for FastAPI-style dependency injection

**Fields:**
- `gemini_api_key` (required)
- `clickup_api_key` (optional)
- `gemini_model`, `llm_temperature`, `llm_max_tokens`, `llm_timeout_seconds`
- `db_path`, `log_dir`, `log_level`
- `allowlist_path`, `block_production`
- `app_name`, `environment` (`development` | `staging` | `production`)

### 4.2 `core/models.py`

**Purpose:** Canonical data schemas for the entire application.

**Models:**

| Model | Role |
|-------|------|
| `Severity` | Enum: info, low, medium, high, critical |
| `ScanStatus` | Enum: pending, running, completed, failed, blocked |
| `ScanType` | Enum: api, ui, fuzzing |
| `Finding` | One security issue: title, severity, confidence, evidence, remediation |
| `ScanProgress` | Yielded by generators: step, percent, message, partial_findings |
| `ScanResult` | Final scan output: findings list, severity_counts() helper, metadata |
| `SafetyResult` | Target validation outcome: allowed, reason, is_production |
| `AuditLogEntry` | Compliance trail: event, target, user, details |

### 4.3 `core/llm_client.py`

**Purpose:** Resilient wrapper around Google Gemini API.

**Class: `GeminiClient`**

| Method | Behavior |
|--------|----------|
| `generate_text(prompt)` | Plain text generation. Tenacity retry: 3 attempts, exponential backoff (1s→2s→4s). Retries on `ResourceExhausted`, `ServiceUnavailable`, `DeadlineExceeded`. Logs prompt hash, latency, lengths. |
| `generate_structured(prompt, response_model)` | Appends JSON schema instruction. Strips markdown fences. Validates against Pydantic model. Retries up to 3× on parse/validation failure. Raises `LLMOutputError` if all attempts fail. |

### 4.4 `core/safety.py`

**Purpose:** Prevent accidental scans against production environments.

**Class: `SafetyGuard`**

| Method | Behavior |
|--------|----------|
| `is_allowed(url)` | Matches against `allowed_patterns` (glob via `fnmatch`) |
| `is_blocked(url)` | Matches against `blocked_patterns` (glob via `fnmatch`) |
| `is_production(url)` | Heuristics: contains `prod`/`production`/`live`, starts with `www.`, or lacks dev indicators when `block_production=True` |
| `validate_target(url)` | Deny-first logic: blocked → allowed → production. Logs `AuditLogEntry` for every outcome. Raises `ProductionBlockError` when production is detected and blocking is enabled. |

**Security features:**
- URL-decoding bypass protection (`unquote` before matching)
- IP variant normalization (`localhost` ↔ `127.0.0.1`, `::1`)
- Glob patterns in JSON config (`config/target_allowlist.json`)

### 4.5 `core/storage.py`

**Purpose:** SQLite persistence for scan history and audit logs.

**Tables (SQLAlchemy 2.0 `Mapped[]` style):**

| Table | Columns |
|-------|---------|
| `scans` | scan_id (PK), scan_type, target, status, started_at, completed_at, result_json, metadata_json |
| `audit_log` | id (PK, auto), timestamp, event, target, user, details_json |

**Functions:**
- `get_engine()` → cached SQLite engine (creates parent dir)
- `init_db()` → creates tables
- `get_session()` → context manager with auto commit/rollback/finally
- `save_scan(result)` → serializes full `ScanResult` to JSON, upserts
- `get_scan(scan_id)` → deserializes via `model_validate_json`
- `list_scans(limit, scan_type)` → newest-first, optional type filter
- `log_audit(entry)` → appends to audit log

### 4.6 `core/logging_config.py`

**Purpose:** Structured logging via Loguru.

**Configuration:**
- Console sink: colorized stderr, level from `settings.log_level`
- File sink: `{log_dir}/secureqa_{YYYY-MM-DD}.log`, 10 MB rotation, 7-day retention, zip compression
- Format: `timestamp | level | name:function:line - message`

### 4.7 `core/exporters/`

**Purpose:** Abstract base + concrete exporters for scan results.

| Exporter | Output | Status |
|----------|--------|--------|
| `MarkdownExporter` | Markdown report string | Stub (Phase 1) |
| `CSVExporter` | CSV string | Stub (Phase 1) |
| `ClickUpExporter` | Dict payload | Stub (Phase 1) |

All inherit from `Exporter` ABC and implement `export(result: ScanResult) -> Any`.

### 4.8 `app.py`

**Purpose:** Streamlit entry point. The ONLY file that imports `streamlit` outside `tabs/`.

**Startup:**
1. `configure_logging()` — initializes Loguru
2. `init_db()` — ensures SQLite tables exist

**Layout:**
- 3-column header: logo+name (left), environment badge (right)
- Production warning banner (`st.error`) if `environment == "production"`
- 3 tabs: API Security, UI Security, AI Fuzzing
- Footer: version, GitHub link, phase indicator

### 4.9 `tabs/*`

**Purpose:** Thin UI wrappers. Each exports a `render_*_tab()` function called by `app.py`.

Current state: all three tabs are placeholders displaying "Phase X — Coming Soon" info.

---

## 5. Data Flows

### 5.1 Scan Lifecycle (Future Phases)

```
User enters target URL in Streamlit tab
        ↓
SafetyGuard.validate_target(url)
   ├─ allowed → proceed
   ├─ blocked → show error + audit log
   └─ production + block_production=True → ProductionBlockError
        ↓
LLM / test engine generates findings
   ├─ yields ScanProgress objects (for UI progress bar)
   └─ completes with ScanResult
        ↓
Save to SQLite (save_scan)
        ↓
Export via Markdown / CSV / ClickUp
```

### 5.2 Audit Trail

Every `validate_target` call logs an `AuditLogEntry`:
- `target_validated` — passed all checks
- `target_blocked` — failed allowlist or blocklist
- `prod_blocked` — production target blocked by policy

Entries are persisted to `audit_log` table via `log_audit()`.

### 5.3 LLM Call Lifecycle

```
Tab calls GeminiClient.generate_text() or generate_structured()
        ↓
genai.GenerativeModel.generate_content()
   ├─ API error (rate limit / unavailable / timeout)
   │   └─ Tenacity retries (3×, exponential backoff)
   └─ Success
        ↓
For structured: strip markdown → JSON.parse → Pydantic.validate
   ├─ Validation fail → retry LLM call (up to 3× total)
   └─ Success → return model instance
```

---

## 6. Build & Setup Steps

### 6.1 Initial Setup

```bash
# 1. Clone repository
git clone https://github.com/Yusuf-Hridoy/secureqa-orchestrator.git
cd secureqa-orchestrator

# 2. Create virtual environment
python -m venv .venv

# 3. Activate (Windows PowerShell)
.venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements-dev.txt

# 5. Configure environment
copy .env.example .env
# Edit .env and set GEMINI_API_KEY
```

### 6.2 Running the Application

```bash
streamlit run app.py
```

### 6.3 Running Tests

```bash
# Run all tests
pytest

# With coverage report
pytest --cov=core --cov-report=term-missing

# Specific test file
pytest tests/test_models.py -v
```

### 6.4 Linting & Formatting

```bash
# Check
ruff check .
ruff format --check .

# Auto-fix
ruff check --fix .
ruff format .
```

---

## 7. Configuration Files

### 7.1 `.env` (not committed)

Created from `.env.example`. Minimum required:
```env
GEMINI_API_KEY=your_key_here
```

### 7.2 `config/target_allowlist.json`

Glob patterns for URL validation:
```json
{
  "allowed_patterns": ["*.staging.*", "localhost", "localhost:*"],
  "blocked_patterns": ["*.prod.*", "*production*", "www.*"]
}
```

**Rule:** BLOCKED takes precedence over ALLOWED.

### 7.3 `config/app_config.yaml`

UI defaults and feature flags:
```yaml
ui:
  theme: light
  primary_color: "#2563EB"

feature_flags:
  enable_clickup_export: true
  enable_auto_classification: false
```

### 7.4 `pyproject.toml`

Tool configurations:
- **ruff:** line-length 100, py311 target, select E/F/W/I/B/UP/N/SIM
- **pytest:** testpaths `tests/`, verbose, strict markers
- **coverage:** source `core/`, `config/`
- **mypy:** py311, ignore missing imports

---

## 8. Testing Strategy

| Layer | Approach | Fixtures |
|-------|----------|----------|
| Models | Pydantic validation, serialization | `sample_finding`, `sample_scan_result` |
| Safety | Temporary allowlist JSON + monkeypatch | `guard` (tmp_path-based) |
| Storage | In-memory SQLite + monkeypatch `get_engine` | `in_memory_engine`, `patched_engine` |
| LLM Client | Mock `google.generativeai` | `mock_genai_model`, `mock_gemini_response` |
| Exporters | Instantiation + stub output checks | `sample_scan_result` |

**Key testing patterns:**
- `monkeypatch.setattr("core.storage.get_engine", lambda: in_memory_engine)` — isolates DB tests
- `mocker.patch("core.safety.log_audit")` — verifies audit logging without DB writes
- `side_effect = [Exception, Exception, Success]` — tests tenacity retry behavior

---

## 9. Extension Points (Future Phases)

### Phase 1: API Security Validator
- **Module:** `tabs/api_security.py`, `core/api_validator.py` (new)
- **Features:** OpenAPI spec upload, BOLA/broken auth tests, Newman runner
- **Prompts:** Add to `prompts/api_security/`

### Phase 2: UI Security & Session Agent
- **Module:** `tabs/ui_security.py`, `core/ui_agent.py` (new)
- **Features:** Playwright browser automation, XSS/CSRF detection, cookie/header checks
- **Dependencies:** Add `playwright` to `requirements.txt`

### Phase 3: AI Fuzzing & Input Agent
- **Module:** `tabs/ai_fuzzing.py`, `core/fuzzing_engine.py` (new)
- **Features:** LLM payload generation, response classification matrix, severity triage
- **Toggle:** `feature_flags.enable_auto_classification` in `app_config.yaml`

### FastAPI Migration Path
1. Move `app.py` logic to `main.py` (FastAPI app)
2. Replace `st.tabs` with API routers
3. Replace `st.session_state` with Redis/database sessions
4. Reuse `core/` modules unchanged — zero business logic migration

---

## 10. Security Considerations

1. **Production Block:** `SafetyGuard` prevents scanning production URLs. Configurable via `target_allowlist.json`.
2. **API Key Management:** `SecretStr` ensures API keys are masked in logs and error traces.
3. **Audit Trail:** Every scan attempt (allowed or blocked) is logged to SQLite with timestamp, user, and target.
4. **No Credential Storage:** `.env` is gitignored. Keys are never persisted in the database.

---

## 11. Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| `ValidationError: gemini_api_key missing` | `.env` not created or key not set | `cp .env.example .env` and add key |
| `ModuleNotFoundError: tabs.ai_fuzzing` | Missing tab placeholder files | Already resolved in Phase 0 (all tabs created) |
| `pytest` collection errors from `config.settings` | `.env` missing required fields | Create `.env` or set env vars before running tests |
| Ruff import sorting errors | Imports not in isort order | Run `ruff check --fix .` |

---

## 12. Changelog

### Phase 0 — Shared Foundation (Complete)
- Project skeleton with strict directory structure
- Pydantic v2 models (`core/models.py`)
- pydantic-settings configuration (`config/settings.py`)
- Loguru logging with rotation (`core/logging_config.py`)
- SQLite storage layer with SQLAlchemy 2.0 (`core/storage.py`)
- Safety guard with allowlist/blocklist (`core/safety.py`)
- Gemini LLM client with tenacity retry (`core/llm_client.py`)
- Exporter ABC + 3 stubs (`core/exporters/`)
- Streamlit app shell with tab layout (`app.py`, `tabs/`)
- pytest test suite (28 tests, all passing)

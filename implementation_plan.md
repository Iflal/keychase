# 🔑 KeyHunter — Path B Implementation Plan

> Transform the prototype into a **professional, pip-installable, open-source secret scanner CLI** that developers actually want to use.

---

## Background

The current repo has two files (`app.py` and `test_code.py`) that duplicate a `GitHubAPIScanner` class with 5 hardcoded regex patterns. The scanner only works via the GitHub REST API (slow, rate-limited, no local or git-history support). There are no tests, no packaging, no CI, and no license.

We will restructure this into a proper Python package called **`keyhunter`** with a modular architecture, 50+ detection patterns, local filesystem & git history scanning, a beautiful Rich-powered CLI, and full PyPI readiness.

---

## User Review Required

> [!IMPORTANT]
> **Naming:** This plan uses `keyhunter` as the package/command name. We should verify PyPI availability before publishing. If taken, fallback candidates: `key-hunter`, `secretsweep`, `credscan`.

> [!IMPORTANT]
> **License:** Plan uses **MIT License** for maximum adoption. If you prefer Apache-2.0 or another license, let me know.

> [!WARNING]
> **Breaking change:** The old `streamlit run app.py` workflow will be **replaced** by a standalone CLI (`keyhunter scan ...`). The Streamlit UI will be removed from the core package. It can be rebuilt later as a separate SaaS frontend (Path A) that imports the `keyhunter` library.

---

## Proposed Changes

### Phase 1 — Foundation & Packaging

Set up project scaffolding, packaging, license, and extract the core scanner into a proper module.

---

#### [NEW] [pyproject.toml](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/pyproject.toml)
- Project metadata (name, version `0.1.0`, description, author, license)
- Dependencies: `requests`, `rich`, `typer`, `gitpython`
- Dev dependencies: `pytest`, `pytest-cov`, `ruff`
- `[project.scripts]` entry point: `keyhunter = "keyhunter.cli:app"`
- Build system: `hatchling`

#### [NEW] [LICENSE](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/LICENSE)
- MIT License

#### [NEW] [.gitignore](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/.gitignore)
- Standard Python gitignore (venv, __pycache__, dist, .eggs, etc.)

---

### Phase 2 — Core Engine (`keyhunter/` package)

The heart of the product. Modular, testable, zero UI dependency.

---

#### [NEW] [keyhunter/\_\_init\_\_.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/__init__.py)
- Package version (`__version__ = "0.1.0"`)

#### [NEW] [keyhunter/detectors/\_\_init\_\_.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/detectors/__init__.py)
- `DetectorRegistry` class — auto-discovers and loads all detector modules
- Each detector is a dataclass: `Detector(id, name, pattern, severity, description)`
- `registry.scan_line(line) -> list[Match]`

#### [NEW] [keyhunter/detectors/aws.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/detectors/aws.py)
- AWS Access Key ID (`AKIA...`)
- AWS Secret Access Key
- AWS MWS Key
- AWS Session Token

#### [NEW] [keyhunter/detectors/gcp.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/detectors/gcp.py)
- Google API Key (`AIza...`)
- GCP Service Account JSON key
- Google OAuth Client Secret

#### [NEW] [keyhunter/detectors/github.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/detectors/github.py)
- GitHub PAT (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- GitHub Fine-grained PAT (`github_pat_`)
- GitHub OAuth App secret

#### [NEW] [keyhunter/detectors/cloud_providers.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/detectors/cloud_providers.py)
- Azure Storage Key, Azure AD Client Secret
- DigitalOcean PAT, Spaces key
- Heroku API Key

#### [NEW] [keyhunter/detectors/payments.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/detectors/payments.py)
- Stripe Secret Key (`sk_live_`, `sk_test_`)
- Stripe Webhook Secret
- PayPal Client Secret
- Square Access Token

#### [NEW] [keyhunter/detectors/messaging.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/detectors/messaging.py)
- Slack Token (`xox[pobas]-...`), Webhook URL
- Twilio Account SID, Auth Token
- SendGrid API Key (`SG.`)
- Discord Bot Token, Webhook
- Telegram Bot Token

#### [NEW] [keyhunter/detectors/ai_ml.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/detectors/ai_ml.py)
- OpenAI API Key (`sk-`)
- Anthropic API Key (`sk-ant-`)
- Hugging Face Token (`hf_`)
- Cohere API Key
- Google Gemini API Key

#### [NEW] [keyhunter/detectors/databases.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/detectors/databases.py)
- MongoDB connection string (`mongodb+srv://...`)
- PostgreSQL connection string
- MySQL connection string
- Redis URL with password

#### [NEW] [keyhunter/detectors/generic.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/detectors/generic.py)
- Generic `password = "..."` / `secret = "..."` / `token = "..."` assignments
- Private keys (RSA, SSH, PGP headers)
- Bearer tokens in code
- Base64-encoded credential blobs
- JWT tokens
- High-entropy strings (Shannon entropy detection)

---

#### [NEW] [keyhunter/scanner/\_\_init\_\_.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/scanner/__init__.py)

#### [NEW] [keyhunter/scanner/base.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/scanner/base.py)
- Abstract `BaseScanner` class
- Defines interface: `scan() -> ScanResult`
- `ScanResult` dataclass: `findings: list[Finding]`, `files_scanned: int`, `duration: float`
- `Finding` dataclass: `file_path`, `line_number`, `detector_id`, `detector_name`, `severity`, `snippet`, `commit_sha` (optional)

#### [NEW] [keyhunter/scanner/local_scanner.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/scanner/local_scanner.py)
- Scans a local directory tree (walks filesystem with `pathlib`)
- Respects `.gitignore` via `pathspec` library patterns
- Respects `.keyhunterignore` custom allowlist
- Filters by file extension & sensitive filename keywords
- Skips binary files (checks for null bytes)

#### [NEW] [keyhunter/scanner/git_history_scanner.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/scanner/git_history_scanner.py)
- Uses `gitpython` to walk commit diffs
- Scans each diff patch for secret patterns
- Records `commit_sha`, `author`, `date` on each finding
- Configurable depth: `--history-depth N` (default: all commits)

#### [NEW] [keyhunter/scanner/github_scanner.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/scanner/github_scanner.py)
- Refactored version of the existing `GitHubAPIScanner`
- Proper rate-limit handling: reads `X-RateLimit-Remaining` and `X-RateLimit-Reset` headers, sleeps with exponential backoff
- Uses `ref=` query param for branch targeting (already partially done)
- Returns `ScanResult` (no UI dependency)

---

#### [NEW] [keyhunter/config.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/config.py)
- `ScanConfig` dataclass: target path, file extensions, excluded dirs, custom patterns path, history depth, output format
- Loads `.keyhunterignore` file for allowlisting false positives
- Env var support: `KEYHUNTER_GITHUB_TOKEN`, etc.

---

### Phase 3 — CLI & Reporters

The user-facing shell. Beautiful, fast, zero-config.

---

#### [NEW] [keyhunter/cli.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/cli.py)
- Built with `typer`
- Commands:
  - `keyhunter scan <path>` — scan local directory (default: `.`)
  - `keyhunter scan <owner/repo>` — detect GitHub format & scan via API
  - `keyhunter scan --history` — include git history
  - `keyhunter scan --format json|table|sarif` — output format
  - `keyhunter hook install` — install as pre-commit hook (future phase)
  - `keyhunter version` — print version
- Exit code `1` if secrets found (CI-friendly)
- Rich progress bars, colored severity badges

#### [NEW] [keyhunter/reporters/\_\_init\_\_.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/reporters/__init__.py)

#### [NEW] [keyhunter/reporters/console.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/reporters/console.py)
- Rich-powered terminal output
- Color-coded severity: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW
- Summary table at the end
- File-grouped findings with snippets

#### [NEW] [keyhunter/reporters/json_reporter.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/reporters/json_reporter.py)
- Structured JSON output for piping / automation

#### [NEW] [keyhunter/reporters/sarif.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/keyhunter/reporters/sarif.py)
- SARIF v2.1.0 format for GitHub Code Scanning integration

---

### Phase 4 — Tests, CI/CD, and Docs

---

#### [NEW] [tests/\_\_init\_\_.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/tests/__init__.py)

#### [NEW] [tests/test_detectors.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/tests/test_detectors.py)
- Unit tests for every detector pattern (true positives + false positives)
- Tests that the registry auto-discovers all modules

#### [NEW] [tests/test_local_scanner.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/tests/test_local_scanner.py)
- Creates temp directories with fixture files containing fake secrets
- Verifies scanner finds them and respects `.keyhunterignore`

#### [NEW] [tests/test_cli.py](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/tests/test_cli.py)
- Uses `typer.testing.CliRunner` to test CLI commands
- Verifies exit codes (0 = clean, 1 = secrets found)

#### [NEW] [tests/fixtures/](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/tests/fixtures/)
- Sample files with intentional fake secrets for testing

---

#### [NEW] [.github/workflows/ci.yml](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/.github/workflows/ci.yml)
- Runs on push/PR to `main`
- Matrix: Python 3.10, 3.11, 3.12
- Steps: install deps, lint with ruff, run pytest with coverage
- Upload coverage to Codecov

#### [NEW] [.github/workflows/release.yml](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/.github/workflows/release.yml)
- Triggered on GitHub Release tag (`v*`)
- Builds wheel + sdist, publishes to PyPI via trusted publishers

---

#### [MODIFY] [README.MD](file:///c:/Users/Iflal/Desktop/PRAC/Own_project/api_key_finder/README.MD)
- Complete rewrite: professional open-source README
- Logo (use existing `logo/key_hunter_logo.svg`)
- Badges: PyPI version, Python versions, CI status, License
- Quick-start (`pip install keyhunter` → `keyhunter scan .`)
- Feature highlights, pattern coverage list
- Contributing guide, license section

#### [DELETE] test_code.py
- Functionality absorbed into `keyhunter/scanner/github_scanner.py` + `keyhunter/cli.py`

#### [DELETE] app.py
- Streamlit UI removed from the core package. The SaaS frontend (Path A) will be a separate project that imports `keyhunter` as a library dependency.

---

## Final File Tree

```
api_key_finder/
├── keyhunter/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── detectors/
│   │   ├── __init__.py          # DetectorRegistry
│   │   ├── aws.py
│   │   ├── gcp.py
│   │   ├── github.py
│   │   ├── cloud_providers.py
│   │   ├── payments.py
│   │   ├── messaging.py
│   │   ├── ai_ml.py
│   │   ├── databases.py
│   │   └── generic.py
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── base.py              # BaseScanner, Finding, ScanResult
│   │   ├── local_scanner.py
│   │   ├── git_history_scanner.py
│   │   └── github_scanner.py
│   └── reporters/
│       ├── __init__.py
│       ├── console.py
│       ├── json_reporter.py
│       └── sarif.py
├── tests/
│   ├── __init__.py
│   ├── test_detectors.py
│   ├── test_local_scanner.py
│   ├── test_cli.py
│   └── fixtures/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── logo/
│   └── (existing SVG files)
├── pyproject.toml
├── LICENSE
├── .gitignore
└── README.md
```

---

## Open Questions

> [!IMPORTANT]
> 1. **Do you want to keep the Streamlit app (`app.py`) around in a separate folder** (e.g., `legacy/`) for reference, or are you comfortable deleting it entirely?

> [!IMPORTANT]
> 2. **PyPI name:** Should I check if `keyhunter` is available on PyPI now, or do you have a preferred name?

> [!IMPORTANT]
> 3. **Python version support:** Plan targets 3.10+. Acceptable, or do you need 3.9?

---

## Verification Plan

### Automated Tests
```bash
# Install in editable mode
pip install -e ".[dev]"

# Run full test suite
pytest tests/ -v --cov=keyhunter --cov-report=term-missing

# Lint
ruff check keyhunter/ tests/

# Smoke test the CLI
keyhunter scan tests/fixtures/    # should find fake secrets, exit code 1
keyhunter scan --format json tests/fixtures/  # JSON output
keyhunter version                 # prints 0.1.0
```

### Manual Verification
- Run `keyhunter scan .` against the keyhunter repo itself (should find zero secrets — dogfooding)
- Run `keyhunter scan <a-known-leaky-test-repo>` via GitHub API mode
- Verify `pip install .` from a clean virtualenv works end-to-end
- Verify exit code behavior: `keyhunter scan tests/fixtures/ ; echo $?` → `1`

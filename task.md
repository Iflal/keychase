# Keychase Implementation Tasks

## Phase 1 — Foundation & Packaging
- [x] Move obsolete files to `legacy/`
- [x] Create `pyproject.toml`
- [x] Create `LICENSE` (MIT)
- [x] Create `.gitignore`
- [x] Setup `keychase/` skeleton

## Phase 2 — Core Engine
- [ ] Create `keychase/detectors/` (Registry + Detector modules)
  - [ ] `aws.py`
  - [ ] `gcp.py`
  - [ ] `github.py`
  - [ ] `cloud_providers.py`
  - [ ] `payments.py`
  - [ ] `messaging.py`
  - [ ] `ai_ml.py`
  - [ ] `databases.py`
  - [ ] `generic.py`
- [ ] Create `keychase/scanner/`
  - [ ] `base.py`
  - [ ] `local_scanner.py`
  - [ ] `git_history_scanner.py`
  - [ ] `github_scanner.py`
- [ ] Create `keychase/config.py`

## Phase 3 — CLI & Reporters
- [ ] Create `keychase/cli.py` (Typer app)
- [ ] Create `keychase/reporters/`
  - [ ] `console.py` (Rich)
  - [ ] `json_reporter.py`
  - [ ] `sarif.py`

## Phase 4 — Tests, CI/CD, and Docs
- [ ] Create tests suite
- [ ] Create CI/CD workflows
- [ ] Update `README.MD`

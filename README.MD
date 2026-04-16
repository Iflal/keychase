<p align="center">
  <img src="logo/keychase_logo_dark.svg" alt="Keychase Logo" width="280"/>
</p>

<h1 align="center">Keychase</h1>

<p align="center">
  <strong>A fast, flexible, zero-config secret scanner for Git repos and filesystems.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/keychase/"><img src="https://img.shields.io/pypi/v/keychase?color=blue" alt="PyPI"></a>
  <a href="https://pypi.org/project/keychase/"><img src="https://img.shields.io/pypi/pyversions/keychase" alt="Python Versions"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Iflal/keychase" alt="License"></a>
</p>

---

## Why Keychase?

Leaked API keys cost companies **millions** every year. Keychase catches hardcoded secrets before they reach production — in your files, in your git history, and in your GitHub repos.

- **78+ built-in detectors** — AWS, GCP, Azure, GitHub, Stripe, OpenAI, Slack, databases, private keys, and more
- **Zero config** — `pip install keychase && keychase scan .` — that's it
- **Git history scanning** — catch secrets in old commits that were "deleted" but still exist in history
- **CI-friendly** — exit code `1` when secrets are found, `0` when clean
- **Multiple output formats** — beautiful terminal tables, JSON, and SARIF (GitHub Code Scanning)
- **Python-native** — install via pip, extend with custom patterns, no binaries needed

---

## Quick Start

### Install

```bash
pip install keychase
```

### Scan a local directory

```bash
keychase scan .
```

### Scan with git history

```bash
keychase scan . --history
```

### Scan a GitHub repository

```bash
export KEYCHASE_GITHUB_TOKEN=ghp_your_token_here
keychase scan owner/repo
```

### JSON output (for CI/CD pipelines)

```bash
keychase scan . --format json --no-progress
```

### SARIF output (for GitHub Code Scanning)

```bash
keychase scan . --format sarif --output results.sarif
```

---

## CLI Reference

```
Usage: keychase [OPTIONS] COMMAND [ARGS]...

Commands:
  scan        Scan a directory or GitHub repo for secrets
  detectors   List all loaded detectors
  version     Show the keychase version

Scan Options:
  --history, -H          Also scan git commit history
  --depth, -d INTEGER    Max commits to scan (default: all)
  --branch, -b TEXT      Branch to scan
  --format, -f TEXT      Output format: table, json, sarif
  --token, -t TEXT       GitHub token for remote scans
  --patterns, -p TEXT    Path to custom regex patterns file
  --output, -o TEXT      Write report to file
  --no-progress          Disable progress bars (CI mode)
```

---

## Supported Detectors

Keychase ships with **78 detectors** across 9 categories:

| Category | Examples | Count |
|---|---|---|
| **AWS** | Access Key ID, Secret Key, MWS Key, Session Token | 5 |
| **GCP** | API Key, Service Account JSON, OAuth Secrets, Firebase | 5 |
| **GitHub** | PAT (classic + fine-grained), OAuth, Server Tokens | 7 |
| **Cloud Providers** | Azure, DigitalOcean, Heroku, Alibaba | 9 |
| **Payments** | Stripe, PayPal, Square, Shopify | 12 |
| **Messaging** | Slack, Discord, Twilio, SendGrid, Mailgun, Telegram | 12 |
| **AI/ML** | OpenAI, Anthropic, Hugging Face, Cohere, Replicate, Gemini, Pinecone | 8 |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis, JDBC | 6 |
| **Generic** | Passwords, Tokens, Private Keys, Bearer Auth, URLs with creds | 14 |

List all detectors:
```bash
keychase detectors
```

### Custom Patterns

Create a file with one regex per line:

```text
# my_patterns.txt
MYCOMPANY_API_[A-Za-z0-9]{32}
internal_token_[0-9a-f]{64}
```

```bash
keychase scan . --patterns my_patterns.txt
```

---

## Ignoring False Positives

Create a `.keychaseignore` file in your project root:

```text
# Files to exclude from scanning
test_fixtures/
*.test.js
legacy_config.py
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Secret Scan
  run: |
    pip install keychase
    keychase scan . --no-progress --format sarif --output keychase.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: keychase.sarif
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | No secrets found |
| `1` | Secrets detected |
| `2` | Configuration/runtime error |

---

## Development

```bash
# Clone the repo
git clone https://github.com/Iflal/keychase.git
cd keychase

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check keychase/ tests/
```

---

## Roadmap

- [ ] Pre-commit hook integration (`keychase hook install`)
- [ ] Secret verification (check if leaked keys are still active)
- [ ] Entropy-based detection for unknown secret formats
- [ ] Docker image (`docker run keychase scan .`)
- [ ] SaaS dashboard (scan orgs, scheduled scans, PDF reports)

---

## Contributing

Contributions welcome! The easiest way to help:

1. **Add new detectors** — see `keychase/detectors/` for examples
2. **Report false positives** — open an issue with the line that triggered it
3. **Improve patterns** — submit a PR with a test case

---

## License

MIT License — see [LICENSE](LICENSE) for details.

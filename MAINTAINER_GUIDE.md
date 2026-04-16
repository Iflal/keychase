# Keychase Maintainer Guide

This guide is for your personal use. It outlines how the project is structured, how you can test it locally, and the step-by-step process to publish it to the world.

---

## 📂 Project Structure & File Details

Here is a breakdown of what every major part of the Keychase codebase does:

### Core Package (`keychase/`)
*   **`cli.py`**: The entry point for the command-line interface. Built using `typer`. This file defines the `scan`, `version`, and `detectors` commands and parses user arguments.
*   **`config.py`**: Handles configuration management. It reads environment variables (like `KEYCHASE_GITHUB_TOKEN`) and manages scan settings.
*   **`detectors/`**: The brain of the scanner.
    *   `__init__.py`: Contains the `DetectorRegistry` which automatically discovers and loads all detector rules. It also implements the fast-rejection logic using keywords.
    *   `aws.py`, `gcp.py`, `github.py`, etc.: These files contain the specific regex patterns and rules to find secrets for different platforms.
*   **`scanner/`**: The engines that do the actual reading of files/APIs.
    *   `base.py`: Defines the `ScanResult` and `Finding` data models that all scanners must use.
    *   `local_scanner.py`: Walks through your local file system, skipping ignored folders (like `node_modules` or `.git`) and binary files.
    *   `git_history_scanner.py`: Uses `GitPython` to read past commits to find secrets that were hardcoded and then deleted later.
    *   `github_scanner.py`: Talks to the GitHub API to scan remote repositories without downloading them. Manages rate limits automatically.
*   **`reporters/`**: How the results are shown to the user.
    *   `console.py`: Uses the `rich` library to draw beautiful, colorful tables and panels in the terminal.
    *   `json_reporter.py`: Outputs raw JSON data, useful if another script needs to read Keychase's output.
    *   `sarif.py`: Outputs SARIF format, which GitHub uses to draw security alerts in the "Security" tab of a repository.

### Infrastructure & Testing
*   **`tests/`**: Contains automated tests (`pytest`) that ensure the detectors don't break when you update them.
    *   `fixtures/`: Dummy files with fake secrets inside them used to prove the scanner works.
*   **`pyproject.toml`**: The modern Python definition file. It tells `pip` what dependencies Keychase needs and sets the project name and version.
*   **`.github/workflows/`**: GitHub Actions for CI/CD.
    *   `ci.yml`: Runs tests automatically every time you push code.
    *   `release.yml`: Automatically publishes Keychase to PyPI when you create a Release on GitHub.

---

## 🧪 How to Test Keychase on Your Own

To test Keychase, make sure your Conda environment is active:
```bash
conda activate keychase
```

### 1. Run the Automated Tests
This runs all 51 tests to make sure every regex pattern is working perfectly:
```bash
pytest tests/ -v
```

### 2. Test the CLI Locally
You can run Keychase against any folder on your computer.

Scan the Keychase project itself (should be clean except for the test fixtures):
```bash
keychase scan .
```

Scan a specific folder somewhere else on your PC:
```bash
keychase scan C:\Path\To\Another\Project
```

Test the Git History scanner (finds secrets in past commits):
```bash
keychase scan . --history
```

### 3. Test GitHub Scanning
Set your GitHub token in your terminal, then scan a remote repository:
```powershell
$env:KEYCHASE_GITHUB_TOKEN="ghp_your_actual_token_here"
keychase scan Iflal/some-repository
```

---

## 🚀 How to Publish on the Internet (PyPI)

To make `pip install keychase` work for anyone in the world, you need to publish the package to PyPI (Python Package Index).

### Step 1: Create a PyPI Account
1. Go to [https://pypi.org/](https://pypi.org/) and register an account.
2. Enable 2FA (Two-Factor Authentication) on your PyPI account (it is enforced).

### Step 2: Push your code to GitHub
If you haven't already, push this entire project to a repository on your GitHub account.
```bash
git add .
git commit -m "Initial release of Keychase"
git push origin main
```

### Step 3: Setup Trusted Publishing (Recommended & Most Secure)
We have already created the `.github/workflows/release.yml` file. You need to tell PyPI to trust your GitHub repository.
1. Go to your PyPI account settings -> **Publishing**.
2. Scroll to **"Add a new pending publisher"**.
3. Select **GitHub**.
4. Fill in the details:
   * **PyPI Project Name**: `keychase`
   * **Owner**: Your GitHub username (e.g., `Iflal`)
   * **Repository name**: The name of your repo (e.g., `github_api_key_hunter` or `keychase`)
   * **Workflow name**: `release.yml`
5. Click Add.

### Step 4: Publish!
To publish, all you have to do is create a Release on GitHub.
1. Go to your repository on GitHub.com.
2. On the right sidebar, click **Releases** -> **Create a new release**.
3. Click "Choose a tag" and type `v0.1.0`, then click "Create new tag on publish".
4. Set the Release title to `v0.1.0`.
5. Click **Publish release**.

GitHub Actions will automatically catch this event, build your code into a `.whl` package, and upload it to PyPI. 

### Step 5: Verify
Wait about 2 minutes, then open your terminal and try:
```bash
pip install keychase
```
If it installs, you are officially live!

---

## ⏭️ Next Steps You Can Work On

If you want to continue improving Keychase, here are the best next tasks:

1. **Add More Detectors**: Find API key formats for cloud services that aren't covered yet. Add a new regex in `keychase/detectors/generic.py` or a new file. Just remember to write a test for it in `tests/test_detectors.py`.
2. **Pre-commit Hook**: Build a small feature that allows users to run Keychase automatically every time they type `git commit`. If a secret is found, the commit is blocked.
3. **Secret Verification**: Add logic to not just *find* the secret, but ping the respective API (like AWS or Slack) to see if the secret is actually *active/live*, avoiding false alarms on expired keys.
4. **Build a Marketing Website**: Buy `keychase.com` and put up the logo and the CLI installation instructions.

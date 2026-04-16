"""GitHub secret detectors."""

from keychase.detectors import Detector, Severity, _compile

DETECTORS: list[Detector] = [
    Detector(
        id="github-pat-classic",
        name="GitHub Personal Access Token (Classic)",
        pattern=_compile(r"ghp_[a-zA-Z0-9]{36}"),
        severity=Severity.CRITICAL,
        description="Classic GitHub PAT. Grants repository and API access.",
        keywords=("ghp_",),
    ),
    Detector(
        id="github-pat-fine-grained",
        name="GitHub Fine-Grained PAT",
        pattern=_compile(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"),
        severity=Severity.CRITICAL,
        description="GitHub fine-grained personal access token with scoped permissions.",
        keywords=("github_pat_",),
    ),
    Detector(
        id="github-oauth-access-token",
        name="GitHub OAuth Access Token",
        pattern=_compile(r"gho_[a-zA-Z0-9]{36}"),
        severity=Severity.CRITICAL,
        description="GitHub OAuth access token.",
        keywords=("gho_",),
    ),
    Detector(
        id="github-user-to-server-token",
        name="GitHub User-to-Server Token",
        pattern=_compile(r"ghu_[a-zA-Z0-9]{36}"),
        severity=Severity.HIGH,
        description="GitHub App user-to-server token.",
        keywords=("ghu_",),
    ),
    Detector(
        id="github-server-to-server-token",
        name="GitHub Server-to-Server Token",
        pattern=_compile(r"ghs_[a-zA-Z0-9]{36}"),
        severity=Severity.HIGH,
        description="GitHub App server-to-server installation token.",
        keywords=("ghs_",),
    ),
    Detector(
        id="github-refresh-token",
        name="GitHub Refresh Token",
        pattern=_compile(r"ghr_[a-zA-Z0-9]{36}"),
        severity=Severity.HIGH,
        description="GitHub App refresh token.",
        keywords=("ghr_",),
    ),
    Detector(
        id="github-app-private-key",
        name="GitHub App Private Key",
        pattern=_compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        description="RSA private key, often used for GitHub App authentication.",
        keywords=("begin rsa private key",),
    ),
]

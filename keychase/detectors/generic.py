"""
Generic secret detectors.

Catches common hardcoded credentials, private keys, tokens,
and high-entropy strings that don't match a specific vendor.
"""

import math
from keychase.detectors import Detector, Severity, _compile

DETECTORS: list[Detector] = [
    # ── Hardcoded credential assignments ──────────────────────────
    Detector(
        id="generic-password-assignment",
        name="Hardcoded Password",
        pattern=_compile(
            r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]"""
        ),
        severity=Severity.MEDIUM,
        description="Hardcoded password literal in source code.",
        keywords=("password", "passwd", "pwd"),
    ),
    Detector(
        id="generic-secret-assignment",
        name="Hardcoded Secret",
        pattern=_compile(
            r"""(?i)(?:secret|secret_key|api_secret)\s*[:=]\s*['"]([^'"]{8,})['"]"""
        ),
        severity=Severity.MEDIUM,
        description="Hardcoded secret value in source code.",
        keywords=("secret",),
    ),
    Detector(
        id="generic-token-assignment",
        name="Hardcoded Token",
        pattern=_compile(
            r"""(?i)(?:token|auth_token|access_token|api_token)\s*[:=]\s*['"]([^'"]{8,})['"]"""
        ),
        severity=Severity.MEDIUM,
        description="Hardcoded token value in source code.",
        keywords=("token",),
    ),
    Detector(
        id="generic-api-key-assignment",
        name="Hardcoded API Key",
        pattern=_compile(
            r"""(?i)(?:api_key|apikey)\s*[:=]\s*['"]([^'"]{8,})['"]"""
        ),
        severity=Severity.MEDIUM,
        description="Hardcoded API key in source code.",
        keywords=("api_key", "apikey"),
    ),

    # ── Private keys ──────────────────────────────────────────────
    Detector(
        id="private-key-rsa",
        name="RSA Private Key",
        pattern=_compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        description="PEM-encoded RSA private key.",
        keywords=("begin rsa private key",),
    ),
    Detector(
        id="private-key-openssh",
        name="OpenSSH Private Key",
        pattern=_compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        description="OpenSSH private key.",
        keywords=("begin openssh private key",),
    ),
    Detector(
        id="private-key-ec",
        name="EC Private Key",
        pattern=_compile(r"-----BEGIN EC PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        description="PEM-encoded elliptic curve private key.",
        keywords=("begin ec private key",),
    ),
    Detector(
        id="private-key-dsa",
        name="DSA Private Key",
        pattern=_compile(r"-----BEGIN DSA PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        description="PEM-encoded DSA private key.",
        keywords=("begin dsa private key",),
    ),
    Detector(
        id="private-key-generic",
        name="Generic Private Key",
        pattern=_compile(r"-----BEGIN PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        description="PEM-encoded PKCS#8 private key.",
        keywords=("begin private key",),
    ),
    Detector(
        id="pgp-private-key-block",
        name="PGP Private Key Block",
        pattern=_compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        severity=Severity.CRITICAL,
        description="PGP/GPG private key block.",
        keywords=("begin pgp private key",),
    ),

    # ── Bearer tokens in code ─────────────────────────────────────
    Detector(
        id="bearer-token-header",
        name="Bearer Token in Code",
        pattern=_compile(
            r"""(?i)(?:authorization|bearer)\s*[:=]\s*['"]?Bearer\s+[A-Za-z0-9\-_\.]{20,}['"]?"""
        ),
        severity=Severity.HIGH,
        description="Hardcoded Bearer token in an authorization header.",
        keywords=("bearer",),
    ),

    # ── Basic Auth ────────────────────────────────────────────────
    Detector(
        id="basic-auth-header",
        name="Basic Auth Credentials",
        pattern=_compile(
            r"""(?i)(?:authorization)\s*[:=]\s*['"]?Basic\s+[A-Za-z0-9+/=]{10,}['"]?"""
        ),
        severity=Severity.HIGH,
        description="Hardcoded Basic authentication credentials (base64-encoded user:pass).",
        keywords=("basic",),
    ),

    # ── URLs with embedded credentials ────────────────────────────
    Detector(
        id="url-with-credentials",
        name="URL with Embedded Credentials",
        pattern=_compile(
            r"https?://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+"
        ),
        severity=Severity.HIGH,
        description="URL containing embedded username:password credentials.",
        keywords=("://",),
    ),

    # ── .env file content patterns ────────────────────────────────
    Detector(
        id="env-file-export",
        name="Shell Export with Secret",
        pattern=_compile(
            r"""(?i)export\s+(?:.*(?:key|secret|token|password|credential|auth).*)\s*=\s*['"]?[^\s'"]+['"]?"""
        ),
        severity=Severity.MEDIUM,
        description="Shell export statement containing a sensitive-looking variable.",
        keywords=("export",),
    ),
]


# ── Entropy-based detection (helper, not a regex Detector) ────────

def shannon_entropy(data: str, charset: str = "") -> float:
    """
    Calculate the Shannon entropy of a string.
    Higher entropy = more random = more likely to be a secret.

    A typical English sentence has entropy ~3.5-4.5.
    A random hex string has entropy ~3.7-4.0 (for hex charset).
    A random base64 string has entropy ~5.0-6.0.
    """
    if not data:
        return 0.0
    if not charset:
        charset = "".join(set(data))

    length = len(data)
    freq = {c: data.count(c) / length for c in set(data) if c in charset or not charset}
    return -sum(p * math.log2(p) for p in freq.values() if p > 0)


def is_high_entropy(token: str, threshold: float = 4.5) -> bool:
    """
    Check if a string looks like a random secret based on Shannon entropy.
    """
    if len(token) < 16:
        return False
    return shannon_entropy(token) >= threshold

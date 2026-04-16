"""Cloud provider secret detectors (Azure, DigitalOcean, Heroku, etc.)."""

from keychase.detectors import Detector, Severity, _compile

DETECTORS: list[Detector] = [
    # ── Azure ─────────────────────────────────────────────────────
    Detector(
        id="azure-storage-account-key",
        name="Azure Storage Account Key",
        pattern=_compile(
            r"""(?i)(?:account[_\-]?key|storage[_\-]?key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{88})['"]?"""
        ),
        severity=Severity.CRITICAL,
        description="Azure Storage account access key (base64-encoded, 88 chars).",
        keywords=("account_key", "accountkey", "storage_key", "storagekey"),
    ),
    Detector(
        id="azure-ad-client-secret",
        name="Azure AD Client Secret",
        pattern=_compile(
            r"""(?i)(?:azure|aad|ad)[_\-]?(?:client)?[_\-]?secret\s*[:=]\s*['"]?([A-Za-z0-9~._\-]{34,})['"]?"""
        ),
        severity=Severity.CRITICAL,
        description="Azure Active Directory application client secret.",
        keywords=("azure", "client_secret", "aad"),
    ),
    Detector(
        id="azure-connection-string",
        name="Azure Connection String",
        pattern=_compile(
            r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]{88}"
        ),
        severity=Severity.CRITICAL,
        description="Full Azure Storage connection string with embedded key.",
        keywords=("defaultendpointsprotocol", "accountkey"),
    ),

    # ── DigitalOcean ──────────────────────────────────────────────
    Detector(
        id="digitalocean-pat",
        name="DigitalOcean Personal Access Token",
        pattern=_compile(r"dop_v1_[a-f0-9]{64}"),
        severity=Severity.CRITICAL,
        description="DigitalOcean API personal access token.",
        keywords=("dop_v1_",),
    ),
    Detector(
        id="digitalocean-oauth-token",
        name="DigitalOcean OAuth Token",
        pattern=_compile(r"doo_v1_[a-f0-9]{64}"),
        severity=Severity.CRITICAL,
        description="DigitalOcean OAuth application token.",
        keywords=("doo_v1_",),
    ),
    Detector(
        id="digitalocean-refresh-token",
        name="DigitalOcean Refresh Token",
        pattern=_compile(r"dor_v1_[a-f0-9]{64}"),
        severity=Severity.HIGH,
        description="DigitalOcean OAuth refresh token.",
        keywords=("dor_v1_",),
    ),
    Detector(
        id="digitalocean-spaces-key",
        name="DigitalOcean Spaces Access Key",
        pattern=_compile(
            r"""(?i)(?:do|spaces)[_\-]?(?:access)?[_\-]?key\s*[:=]\s*['"]?([A-Z0-9]{20})['"]?"""
        ),
        severity=Severity.HIGH,
        description="DigitalOcean Spaces access key (S3-compatible).",
        keywords=("spaces", "do_access"),
    ),

    # ── Heroku ────────────────────────────────────────────────────
    Detector(
        id="heroku-api-key",
        name="Heroku API Key",
        pattern=_compile(
            r"""(?i)heroku[_\-]?(?:api)?[_\-]?key\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?"""
        ),
        severity=Severity.HIGH,
        description="Heroku platform API key.",
        keywords=("heroku",),
    ),

    # ── Alibaba Cloud ─────────────────────────────────────────────
    Detector(
        id="alibaba-access-key-id",
        name="Alibaba Cloud Access Key ID",
        pattern=_compile(r"(?<![A-Z0-9])LTAI[A-Za-z0-9]{20}(?![A-Za-z0-9])"),
        severity=Severity.CRITICAL,
        description="Alibaba Cloud access key ID.",
        keywords=("ltai",),
    ),
]

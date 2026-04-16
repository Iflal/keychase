"""Google Cloud Platform secret detectors."""

from keychase.detectors import Detector, Severity, _compile

DETECTORS: list[Detector] = [
    Detector(
        id="gcp-api-key",
        name="Google API Key",
        pattern=_compile(r"AIza[0-9A-Za-z\-_]{35}"),
        severity=Severity.HIGH,
        description="Google API key. May grant access to Maps, Firebase, YouTube, and other Google services.",
        keywords=("aiza",),
    ),
    Detector(
        id="gcp-service-account-json",
        name="GCP Service Account Key (JSON)",
        pattern=_compile(
            r"""(?i)("type"\s*:\s*"service_account")"""
        ),
        severity=Severity.CRITICAL,
        description="GCP service account JSON key file. Grants programmatic access to Google Cloud.",
        keywords=("service_account",),
    ),
    Detector(
        id="gcp-oauth-client-secret",
        name="Google OAuth Client Secret",
        pattern=_compile(
            r"""(?i)client[_\-]?secret\s*[:=]\s*['"]?([A-Za-z0-9\-_]{24,})['"]?"""
        ),
        severity=Severity.HIGH,
        description="Google OAuth 2.0 client secret.",
        keywords=("client_secret", "client-secret"),
    ),
    Detector(
        id="gcp-oauth-client-id",
        name="Google OAuth Client ID",
        pattern=_compile(r"\d{12,}-[a-z0-9]{32}\.apps\.googleusercontent\.com"),
        severity=Severity.MEDIUM,
        description="Google OAuth client ID. Not a secret alone, but can aid in social engineering.",
        keywords=("googleusercontent.com",),
    ),
    Detector(
        id="firebase-url",
        name="Firebase Database URL",
        pattern=_compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
        severity=Severity.MEDIUM,
        description="Firebase Realtime Database URL. May allow data access if rules are misconfigured.",
        keywords=("firebaseio.com",),
    ),
]

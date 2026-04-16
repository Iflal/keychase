"""AWS secret detectors."""

from keychase.detectors import Detector, Severity, _compile

DETECTORS: list[Detector] = [
    Detector(
        id="aws-access-key-id",
        name="AWS Access Key ID",
        pattern=_compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        severity=Severity.CRITICAL,
        description="AWS IAM access key ID. Can be used with the secret key to access AWS services.",
        keywords=("akia",),
    ),
    Detector(
        id="aws-secret-access-key",
        name="AWS Secret Access Key",
        pattern=_compile(
            r"""(?i)(?:aws)?[_\-]?secret[_\-]?(?:access)?[_\-]?key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""
        ),
        severity=Severity.CRITICAL,
        description="AWS secret access key. Provides full access to the associated AWS account.",
        keywords=("secret", "aws"),
    ),
    Detector(
        id="aws-mws-key",
        name="AWS MWS Key",
        pattern=_compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        severity=Severity.HIGH,
        description="Amazon Marketplace Web Service key.",
        keywords=("amzn.mws",),
    ),
    Detector(
        id="aws-session-token",
        name="AWS Session Token",
        pattern=_compile(
            r"""(?i)(?:aws)?[_\-]?session[_\-]?token\s*[:=]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?"""
        ),
        severity=Severity.HIGH,
        description="Temporary AWS session credentials.",
        keywords=("session", "token"),
    ),
    Detector(
        id="aws-account-id",
        name="AWS Account ID",
        pattern=_compile(
            r"""(?i)(?:aws)?[_\-]?account[_\-]?id\s*[:=]\s*['"]?(\d{12})['"]?"""
        ),
        severity=Severity.LOW,
        description="AWS 12-digit account ID. Low risk alone but useful in targeted attacks.",
        keywords=("account", "aws"),
    ),
]

"""
Tests for the detector registry and all built-in detector modules.

Validates that every detector correctly matches known secret patterns
(true positives) and does NOT match clean text (false positives).
"""

import pytest

from keychase.detectors import DetectorRegistry, Severity


# ── Helpers ───────────────────────────────────────────────────────

@pytest.fixture
def registry():
    """Fully loaded registry with all built-in detectors."""
    r = DetectorRegistry()
    r.load_builtin_detectors()
    return r


def _assert_detects(registry, line: str, detector_id: str):
    """Assert that scanning `line` produces a match from `detector_id`."""
    matches = registry.scan_line(line)
    ids = [m.detector_id for m in matches]
    assert detector_id in ids, (
        f"Expected detector '{detector_id}' to match line:\n  {line!r}\n"
        f"  Got: {ids}"
    )


def _assert_no_match(registry, line: str, detector_id: str):
    """Assert that scanning `line` does NOT produce a match from `detector_id`."""
    matches = registry.scan_line(line)
    ids = [m.detector_id for m in matches]
    assert detector_id not in ids, (
        f"Detector '{detector_id}' should NOT match line:\n  {line!r}"
    )


# ── Registry tests ───────────────────────────────────────────────

class TestRegistry:
    def test_loads_detectors(self, registry):
        assert registry.count > 50, f"Expected 50+ detectors, got {registry.count}"

    def test_summary_has_all_severities(self, registry):
        summary = registry.summary()
        assert "critical" in summary
        assert "high" in summary

    def test_custom_patterns(self):
        r = DetectorRegistry()
        r.load_custom_patterns({"My Secret": r"MY_SECRET_[0-9]{8}"})
        matches = r.scan_line("Found MY_SECRET_12345678 in code")
        assert len(matches) == 1
        assert matches[0].detector_id == "custom-my-secret"


# ── AWS detectors ────────────────────────────────────────────────

class TestAWS:
    def test_access_key_id(self, registry):
        _assert_detects(registry, 'key = "AKIAIOSFODNN7EXAMPLE"', "aws-access-key-id")

    def test_access_key_id_no_false_positive(self, registry):
        _assert_no_match(registry, "some random AKIA text", "aws-access-key-id")

    def test_secret_access_key(self, registry):
        _assert_detects(
            registry,
            'aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            "aws-secret-access-key",
        )


# ── GCP detectors ────────────────────────────────────────────────

class TestGCP:
    def test_api_key(self, registry):
        _assert_detects(
            registry,
            'GOOGLE_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuvwx"',
            "gcp-api-key",
        )

    def test_service_account_json(self, registry):
        _assert_detects(
            registry,
            '"type": "service_account"',
            "gcp-service-account-json",
        )

    def test_firebase_url(self, registry):
        _assert_detects(
            registry,
            "https://my-app-123.firebaseio.com",
            "firebase-url",
        )


# ── GitHub detectors ─────────────────────────────────────────────

class TestGitHub:
    def test_classic_pat(self, registry):
        _assert_detects(
            registry,
            'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
            "github-pat-classic",
        )

    def test_oauth_token(self, registry):
        _assert_detects(
            registry,
            'gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
            "github-oauth-access-token",
        )

    def test_server_token(self, registry):
        _assert_detects(
            registry,
            "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            "github-server-to-server-token",
        )


# ── Payments detectors ───────────────────────────────────────────

class TestPayments:
    def test_stripe_live(self, registry):
        _assert_detects(
            registry,
            'key = "sk_live_abc123def456ghi789jkl0123456"',
            "stripe-secret-key-live",
        )

    def test_stripe_test(self, registry):
        _assert_detects(
            registry,
            'key = "sk_test_abc123def456ghi789jkl0123456"',
            "stripe-secret-key-test",
        )

    def test_stripe_webhook(self, registry):
        _assert_detects(
            registry,
            'secret = "whsec_abc123def456ghi789jkl01234567890ab"',
            "stripe-webhook-secret",
        )

    def test_square_access_token(self, registry):
        _assert_detects(registry, "sq0atp-abcdefghijKLMNOPQRSTUV", "square-access-token")

    def test_shopify_access_token(self, registry):
        _assert_detects(registry, "shpat_abcdef1234567890abcdef1234567890", "shopify-access-token")


# ── Messaging detectors ──────────────────────────────────────────

class TestMessaging:
    def test_slack_bot_token(self, registry):
        _assert_detects(
            registry,
            "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx",
            "slack-bot-token",
        )

    def test_slack_webhook(self, registry):
        _assert_detects(
            registry,
            "https://hooks.slack.com/services/T1234ABCD/B5678EFGH/abc123xyz",
            "slack-webhook-url",
        )

    def test_sendgrid(self, registry):
        _assert_detects(
            registry,
            "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz12345678901234567",
            "sendgrid-api-key",
        )

    def test_discord_webhook(self, registry):
        _assert_detects(
            registry,
            "https://discord.com/api/webhooks/123456789012345678/abcdefghij-KLMNOPQR",
            "discord-webhook-url",
        )


# ── AI/ML detectors ──────────────────────────────────────────────

class TestAIML:
    def test_openai_project_key(self, registry):
        _assert_detects(
            registry,
            'key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMN"',
            "openai-api-key-v2",
        )

    def test_huggingface_token(self, registry):
        _assert_detects(
            registry,
            "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
            "huggingface-token",
        )

    def test_replicate_token(self, registry):
        _assert_detects(
            registry,
            "r8_abcdefghijklmnopqrstuvwxyz1234567890AB",
            "replicate-api-token",
        )


# ── Database detectors ───────────────────────────────────────────

class TestDatabases:
    def test_mongodb(self, registry):
        _assert_detects(
            registry,
            'url = "mongodb+srv://admin:pass123@cluster0.example.net/db"',
            "mongodb-connection-string",
        )

    def test_postgresql(self, registry):
        _assert_detects(
            registry,
            "postgresql://user:p4ssw0rd@localhost:5432/mydb",
            "postgresql-connection-string",
        )

    def test_redis(self, registry):
        _assert_detects(
            registry,
            "redis://default:secretpass@redis.example.com:6379",
            "redis-connection-string",
        )

    def test_mysql(self, registry):
        _assert_detects(
            registry,
            "mysql://root:password@localhost:3306/app",
            "mysql-connection-string",
        )


# ── Generic detectors ────────────────────────────────────────────

class TestGeneric:
    def test_password_assignment(self, registry):
        _assert_detects(
            registry,
            'password = "hunter2_is_not_a_good_password"',
            "generic-password-assignment",
        )

    def test_rsa_private_key(self, registry):
        _assert_detects(
            registry,
            "-----BEGIN RSA PRIVATE KEY-----",
            "private-key-rsa",
        )

    def test_openssh_private_key(self, registry):
        _assert_detects(
            registry,
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "private-key-openssh",
        )

    def test_bearer_token(self, registry):
        _assert_detects(
            registry,
            'Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123"',
            "bearer-token-header",
        )

    def test_url_with_credentials(self, registry):
        _assert_detects(
            registry,
            "https://admin:secret@internal.example.com/api",
            "url-with-credentials",
        )

    def test_clean_line_no_match(self, registry):
        """A normal code line should produce zero matches."""
        matches = registry.scan_line("def hello():")
        assert len(matches) == 0

    def test_comment_no_false_positive(self, registry):
        """A comment mentioning 'password' without assignment should not match."""
        matches = registry.scan_line("# Remember to set your password via env vars")
        assert len(matches) == 0

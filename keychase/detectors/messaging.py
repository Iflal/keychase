"""Messaging & communication platform secret detectors."""

from keychase.detectors import Detector, Severity, _compile

DETECTORS: list[Detector] = [
    # ── Slack ─────────────────────────────────────────────────────
    Detector(
        id="slack-bot-token",
        name="Slack Bot Token",
        pattern=_compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        severity=Severity.HIGH,
        description="Slack bot user OAuth token.",
        keywords=("xoxb-",),
    ),
    Detector(
        id="slack-user-token",
        name="Slack User Token",
        pattern=_compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}"),
        severity=Severity.CRITICAL,
        description="Slack user OAuth token. Can impersonate a user.",
        keywords=("xoxp-",),
    ),
    Detector(
        id="slack-app-token",
        name="Slack App-Level Token",
        pattern=_compile(r"xapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-z0-9]+"),
        severity=Severity.HIGH,
        description="Slack app-level token for Socket Mode or event subscriptions.",
        keywords=("xapp-",),
    ),
    Detector(
        id="slack-webhook-url",
        name="Slack Incoming Webhook URL",
        pattern=_compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
        severity=Severity.MEDIUM,
        description="Slack incoming webhook URL. Can post messages to a channel.",
        keywords=("hooks.slack.com",),
    ),

    # ── Discord ───────────────────────────────────────────────────
    Detector(
        id="discord-bot-token",
        name="Discord Bot Token",
        pattern=_compile(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}"),
        severity=Severity.HIGH,
        description="Discord bot authentication token.",
        keywords=(),  # No reliable keyword; token format is distinctive enough
    ),
    Detector(
        id="discord-webhook-url",
        name="Discord Webhook URL",
        pattern=_compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+"),
        severity=Severity.MEDIUM,
        description="Discord webhook URL. Can post messages and embeds to a channel.",
        keywords=("discord", "webhooks"),
    ),

    # ── Twilio ────────────────────────────────────────────────────
    Detector(
        id="twilio-account-sid",
        name="Twilio Account SID",
        pattern=_compile(r"AC[a-f0-9]{32}"),
        severity=Severity.MEDIUM,
        description="Twilio account SID. Not secret alone but identifies the account.",
        keywords=("ac",),
    ),
    Detector(
        id="twilio-auth-token",
        name="Twilio Auth Token",
        pattern=_compile(
            r"""(?i)twilio[_\-]?(?:auth)?[_\-]?token\s*[:=]\s*['"]?([a-f0-9]{32})['"]?"""
        ),
        severity=Severity.CRITICAL,
        description="Twilio authentication token. Grants full API access.",
        keywords=("twilio", "auth_token"),
    ),
    Detector(
        id="twilio-api-key",
        name="Twilio API Key",
        pattern=_compile(r"SK[a-f0-9]{32}"),
        severity=Severity.HIGH,
        description="Twilio API key SID.",
        keywords=("sk",),
    ),

    # ── SendGrid ──────────────────────────────────────────────────
    Detector(
        id="sendgrid-api-key",
        name="SendGrid API Key",
        pattern=_compile(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"),
        severity=Severity.HIGH,
        description="SendGrid API key. Can send emails and access account data.",
        keywords=("sg.",),
    ),

    # ── Mailgun ───────────────────────────────────────────────────
    Detector(
        id="mailgun-api-key",
        name="Mailgun API Key",
        pattern=_compile(r"key-[0-9a-zA-Z]{32}"),
        severity=Severity.HIGH,
        description="Mailgun API key.",
        keywords=("key-",),
    ),

    # ── Telegram ──────────────────────────────────────────────────
    Detector(
        id="telegram-bot-token",
        name="Telegram Bot Token",
        pattern=_compile(r"[0-9]{8,10}:[A-Za-z0-9_-]{35}"),
        severity=Severity.HIGH,
        description="Telegram Bot API token.",
        keywords=(),  # No reliable keyword
    ),
]

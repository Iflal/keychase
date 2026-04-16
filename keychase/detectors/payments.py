"""Payment platform secret detectors (Stripe, PayPal, Square, etc.)."""

from keychase.detectors import Detector, Severity, _compile

DETECTORS: list[Detector] = [
    # ── Stripe ────────────────────────────────────────────────────
    Detector(
        id="stripe-secret-key-live",
        name="Stripe Live Secret Key",
        pattern=_compile(r"sk_live_[a-zA-Z0-9]{24,}"),
        severity=Severity.CRITICAL,
        description="Stripe live-mode secret key. Can process real payments and access customer data.",
        keywords=("sk_live_",),
    ),
    Detector(
        id="stripe-secret-key-test",
        name="Stripe Test Secret Key",
        pattern=_compile(r"sk_test_[a-zA-Z0-9]{24,}"),
        severity=Severity.MEDIUM,
        description="Stripe test-mode secret key. Cannot process real payments but reveals account structure.",
        keywords=("sk_test_",),
    ),
    Detector(
        id="stripe-publishable-key-live",
        name="Stripe Live Publishable Key",
        pattern=_compile(r"pk_live_[a-zA-Z0-9]{24,}"),
        severity=Severity.LOW,
        description="Stripe live publishable key. Meant to be public but may indicate a live integration.",
        keywords=("pk_live_",),
    ),
    Detector(
        id="stripe-restricted-key",
        name="Stripe Restricted Key",
        pattern=_compile(r"rk_live_[a-zA-Z0-9]{24,}"),
        severity=Severity.HIGH,
        description="Stripe restricted API key with limited permissions.",
        keywords=("rk_live_",),
    ),
    Detector(
        id="stripe-webhook-secret",
        name="Stripe Webhook Signing Secret",
        pattern=_compile(r"whsec_[a-zA-Z0-9]{32,}"),
        severity=Severity.HIGH,
        description="Stripe webhook endpoint signing secret.",
        keywords=("whsec_",),
    ),

    # ── PayPal ────────────────────────────────────────────────────
    Detector(
        id="paypal-braintree-access-token",
        name="PayPal Braintree Access Token",
        pattern=_compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
        severity=Severity.CRITICAL,
        description="PayPal/Braintree production access token.",
        keywords=("access_token$production$",),
    ),

    # ── Square ────────────────────────────────────────────────────
    Detector(
        id="square-access-token",
        name="Square Access Token",
        pattern=_compile(r"sq0atp-[0-9A-Za-z\-_]{22}"),
        severity=Severity.CRITICAL,
        description="Square API access token.",
        keywords=("sq0atp-",),
    ),
    Detector(
        id="square-oauth-secret",
        name="Square OAuth Secret",
        pattern=_compile(r"sq0csp-[0-9A-Za-z\-_]{43}"),
        severity=Severity.CRITICAL,
        description="Square OAuth application secret.",
        keywords=("sq0csp-",),
    ),

    # ── Shopify ───────────────────────────────────────────────────
    Detector(
        id="shopify-access-token",
        name="Shopify Access Token",
        pattern=_compile(r"shpat_[a-fA-F0-9]{32}"),
        severity=Severity.HIGH,
        description="Shopify Admin API access token.",
        keywords=("shpat_",),
    ),
    Detector(
        id="shopify-custom-app-token",
        name="Shopify Custom App Access Token",
        pattern=_compile(r"shpca_[a-fA-F0-9]{32}"),
        severity=Severity.HIGH,
        description="Shopify custom app access token.",
        keywords=("shpca_",),
    ),
    Detector(
        id="shopify-private-app-password",
        name="Shopify Private App Password",
        pattern=_compile(r"shppa_[a-fA-F0-9]{32}"),
        severity=Severity.HIGH,
        description="Shopify private app password.",
        keywords=("shppa_",),
    ),
    Detector(
        id="shopify-shared-secret",
        name="Shopify Shared Secret",
        pattern=_compile(r"shpss_[a-fA-F0-9]{32}"),
        severity=Severity.HIGH,
        description="Shopify shared secret for webhook verification.",
        keywords=("shpss_",),
    ),
]

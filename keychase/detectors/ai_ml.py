"""AI / ML platform secret detectors."""

from keychase.detectors import Detector, Severity, _compile

DETECTORS: list[Detector] = [
    # ── OpenAI ────────────────────────────────────────────────────
    Detector(
        id="openai-api-key",
        name="OpenAI API Key",
        pattern=_compile(r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"),
        severity=Severity.HIGH,
        description="OpenAI API key. Grants access to GPT, DALL-E, and Whisper APIs.",
        keywords=("sk-",),
    ),
    Detector(
        id="openai-api-key-v2",
        name="OpenAI API Key (Project)",
        pattern=_compile(r"sk-proj-[a-zA-Z0-9\-_]{48,}"),
        severity=Severity.HIGH,
        description="OpenAI project-scoped API key.",
        keywords=("sk-proj-",),
    ),

    # ── Anthropic ─────────────────────────────────────────────────
    Detector(
        id="anthropic-api-key",
        name="Anthropic API Key",
        pattern=_compile(r"sk-ant-api03-[a-zA-Z0-9\-_]{93}"),
        severity=Severity.HIGH,
        description="Anthropic (Claude) API key.",
        keywords=("sk-ant-",),
    ),

    # ── Hugging Face ──────────────────────────────────────────────
    Detector(
        id="huggingface-token",
        name="Hugging Face Access Token",
        pattern=_compile(r"hf_[a-zA-Z0-9]{34}"),
        severity=Severity.HIGH,
        description="Hugging Face user access token.",
        keywords=("hf_",),
    ),

    # ── Cohere ────────────────────────────────────────────────────
    Detector(
        id="cohere-api-key",
        name="Cohere API Key",
        pattern=_compile(
            r"""(?i)cohere[_\-]?(?:api)?[_\-]?key\s*[:=]\s*['"]?([a-zA-Z0-9]{40})['"]?"""
        ),
        severity=Severity.HIGH,
        description="Cohere NLP platform API key.",
        keywords=("cohere",),
    ),

    # ── Replicate ─────────────────────────────────────────────────
    Detector(
        id="replicate-api-token",
        name="Replicate API Token",
        pattern=_compile(r"r8_[a-zA-Z0-9]{38}"),
        severity=Severity.HIGH,
        description="Replicate platform API token.",
        keywords=("r8_",),
    ),

    # ── Google Gemini / AI Studio ─────────────────────────────────
    Detector(
        id="google-gemini-api-key",
        name="Google Gemini API Key",
        pattern=_compile(
            r"""(?i)(?:gemini|ai[_\-]?studio)[_\-]?(?:api)?[_\-]?key\s*[:=]\s*['"]?(AIza[0-9A-Za-z\-_]{35})['"]?"""
        ),
        severity=Severity.HIGH,
        description="Google Gemini / AI Studio API key.",
        keywords=("gemini", "ai_studio", "aiza"),
    ),

    # ── Pinecone ──────────────────────────────────────────────────
    Detector(
        id="pinecone-api-key",
        name="Pinecone API Key",
        pattern=_compile(
            r"""(?i)pinecone[_\-]?(?:api)?[_\-]?key\s*[:=]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?"""
        ),
        severity=Severity.HIGH,
        description="Pinecone vector database API key.",
        keywords=("pinecone",),
    ),
]

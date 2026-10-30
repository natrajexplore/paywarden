"""Central configuration. All secrets come from the environment — never from code or the LLM.

Fail closed: with PAYWARDEN_DEMO_MODE=false the process refuses to start if any demo default,
weak or missing secret is present (PCI DSS 2.2.2 vendor defaults, 8.3.6 credential strength;
NYDFS 500.7; CIS Controls 4.7). Demo mode keeps the zero-setup judge experience.
"""
from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .security.crypto import derive_key
from .security.redact import LEVELS

try:  # optional, for local dev
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass

BASE_DIR = Path(__file__).resolve().parent.parent

# Public demo values (documented in README for judges). Refused when demo mode is off.
DEMO_TOKENS = {"maker": "demo-maker-token", "checker": "demo-checker-token"}
DEMO_TOTP = {"maker": "JBSWY3DPEHPK3PXP", "checker": "KRSXG5CTMVRXEZLU"}
DEMO_AGENT_TOKEN = "demo-agent-token"
PAYPAL_SANDBOX_HOSTS = {"api-m.sandbox.paypal.com", "api.sandbox.paypal.com"}


def _env(name: str, default: str | None = None) -> str | None:
    val = os.getenv(name, default)
    return val if val not in ("", None) else default


def _key32(name: str) -> tuple[bytes, bool]:
    """Load a 32-byte key (base64) from env -> (key, ephemeral?)."""
    raw = _env(name)
    if raw:
        key = base64.b64decode(raw)
        if len(key) != 32:
            raise ValueError(f"{name} must be 32 bytes base64-encoded")
        return key, False
    # Ephemeral key: data encrypted in this run cannot be read after restart. Demo mode only.
    return secrets.token_bytes(32), True


@dataclass
class Settings:
    demo_mode: bool = field(default_factory=lambda: (_env("PAYWARDEN_DEMO_MODE", "true") or "").lower() == "true")

    # PayPal (sandbox only for the hackathon)
    paypal_client_id: str | None = field(default_factory=lambda: _env("PAYPAL_CLIENT_ID"))
    paypal_client_secret: str | None = field(default_factory=lambda: _env("PAYPAL_CLIENT_SECRET"))
    paypal_base_url: str = field(
        default_factory=lambda: _env("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
    )
    paypal_webhook_id: str | None = field(default_factory=lambda: _env("PAYPAL_WEBHOOK_ID"))

    # AI
    anthropic_api_key: str | None = field(default_factory=lambda: _env("ANTHROPIC_API_KEY"))
    anthropic_model: str = field(default_factory=lambda: _env("ANTHROPIC_MODEL", "claude-opus-5-5"))
    # TypeSafe Jev decision model (preferred when its key is set). Pin a version, e.g. jev-1.14.0.
    typesafe_api_key: str | None = field(default_factory=lambda: _env("TYPESAFE_API_KEY"), repr=False)
    typesafe_model: str = field(default_factory=lambda: _env("TYPESAFE_MODEL", "jev-latest"))
    redaction_level: str = field(default_factory=lambda: (_env("PAYWARDEN_REDACTION", "standard") or "").lower())

    # Master keys (one per domain); purpose keys are derived with HKDF in __post_init__
    _data: tuple = field(default_factory=lambda: _key32("PAYWARDEN_DATA_KEY"), repr=False)
    _audit: tuple = field(default_factory=lambda: _key32("PAYWARDEN_AUDIT_KEY"), repr=False)

    # Operators (maker/checker): each has their own bearer token and TOTP seed (base32).
    operator_tokens: dict = field(default_factory=lambda: {
        op: _env(f"OPERATOR_{op.upper()}_TOKEN", DEMO_TOKENS[op]) for op in DEMO_TOKENS}, repr=False)
    operator_totp: dict = field(default_factory=lambda: {
        op: _env(f"OPERATOR_{op.upper()}_TOTP", DEMO_TOTP[op]) for op in DEMO_TOTP}, repr=False)
    # External AI agents (e.g. via the MCP server): propose-only credential, never an operator.
    agent_token: str = field(default_factory=lambda: _env("PAYWARDEN_AGENT_TOKEN", DEMO_AGENT_TOKEN), repr=False)
    mfa_max_failures: int = field(default_factory=lambda: int(_env("MFA_MAX_FAILURES", "5")))
    mfa_lockout_seconds: int = field(default_factory=lambda: int(_env("MFA_LOCKOUT_SECONDS", "900")))

    max_body_bytes: int = field(default_factory=lambda: int(_env("MAX_BODY_BYTES", str(128 * 1024))))
    webhook_tolerance_seconds: int = 300

    db_path: str = field(default_factory=lambda: _env("PAYWARDEN_DB", str(BASE_DIR / "data" / "paywarden.db")))
    allowed_origins: list[str] = field(
        default_factory=lambda: (_env("ALLOWED_ORIGINS", "http://localhost:8000") or "").split(",")
    )

    def __post_init__(self) -> None:
        self.ephemeral_keys = self._data[1] or self._audit[1]
        self.enc_key = derive_key(self._data[0], "enc")            # AES-256-GCM field encryption
        self.bidx_key = derive_key(self._data[0], "blind-index")   # HMAC payee lookup
        self.audit_key = derive_key(self._audit[0], "audit")       # HMAC audit records
        self.binding_key = derive_key(self._audit[0], "binding")   # HMAC approval binding

    @property
    def paypal_live(self) -> bool:
        """True when real sandbox credentials are configured. Production URLs are refused."""
        return bool(self.paypal_client_id and self.paypal_client_secret)

    @property
    def ai_live(self) -> bool:
        return bool(self.typesafe_api_key or self.anthropic_api_key)

    @property
    def ai_engine(self) -> str:
        if self.typesafe_api_key:
            return f"typesafe:{self.typesafe_model}"
        return f"claude:{self.anthropic_model}" if self.anthropic_api_key else "offline-extractor"

    def validate(self) -> None:
        u = urlsplit(self.paypal_base_url)
        if u.scheme != "https" or u.hostname not in PAYPAL_SANDBOX_HOSTS:
            raise RuntimeError(
                "PayWarden hackathon build only talks to the PayPal SANDBOX over HTTPS "
                f"({', '.join(sorted(PAYPAL_SANDBOX_HOSTS))}). Refusing to start."
            )
        if self.redaction_level not in LEVELS:
            raise RuntimeError(f"PAYWARDEN_REDACTION must be one of {LEVELS}")
        if self.demo_mode:
            return
        problems = []
        if self.ephemeral_keys:
            problems.append("PAYWARDEN_DATA_KEY and PAYWARDEN_AUDIT_KEY must be set")
        for op, tok in self.operator_tokens.items():
            if tok == DEMO_TOKENS[op] or len(tok) < 32:
                problems.append(f"OPERATOR_{op.upper()}_TOKEN must be a non-demo secret of >= 32 chars")
        for op, seed in self.operator_totp.items():
            if seed == DEMO_TOTP[op] or len(seed) < 32:
                problems.append(f"OPERATOR_{op.upper()}_TOTP must be a non-demo base32 seed (>= 160 bits)")
        if len(set(self.operator_tokens.values())) != len(self.operator_tokens):
            problems.append("maker and checker tokens must differ (segregation of duties)")
        if self.agent_token == DEMO_AGENT_TOKEN or len(self.agent_token) < 32:
            problems.append("PAYWARDEN_AGENT_TOKEN must be a non-demo secret of >= 32 chars")
        if self.agent_token in self.operator_tokens.values():
            problems.append("PAYWARDEN_AGENT_TOKEN must differ from every operator token")
        if len(set(self.operator_totp.values())) != len(self.operator_totp):
            problems.append("maker and checker TOTP seeds must differ (segregation of duties)")
        if self.redaction_level == "off":
            problems.append("PAYWARDEN_REDACTION=off is only allowed in demo mode")
        if any(o.strip() in ("*", "") for o in self.allowed_origins):
            problems.append("ALLOWED_ORIGINS must list explicit origins")
        if problems:
            raise RuntimeError("Insecure configuration with PAYWARDEN_DEMO_MODE=false:\n  - "
                               + "\n  - ".join(problems))


settings = Settings()
settings.validate()

"""Field-level encryption and masking for PII at rest.

Controls mapped: PCI DSS v4.0.1 Req 3 (protect stored account data — we never store PANs at all,
PayPal holds them), GLBA Safeguards Rule 16 CFR 314.4(c)(3) (encrypt customer info at rest),
GDPR Art. 32 (encryption / pseudonymisation), NYDFS 23 NYCRR 500.15.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_VERSION = b"v1"


def derive_key(master: bytes, label: str) -> bytes:
    """HKDF-SHA256 (RFC 5869). One master key per domain, one derived key per purpose, so a key
    is never reused across algorithms (NIST SP 800-57 Pt 1 §5.2, SP 800-108; PCI DSS 3.6.1)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=f"paywarden/{label}/v1".encode()).derive(master)


def encrypt(plaintext: str, key: bytes, aad: str = "") -> str:
    """AES-256-GCM. Output: base64(version|nonce|ciphertext+tag)."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), aad.encode())
    return base64.urlsafe_b64encode(_VERSION + nonce + ct).decode()


def decrypt(token: str, key: bytes, aad: str = "") -> str:
    raw = base64.urlsafe_b64decode(token.encode())
    if raw[:2] != _VERSION:
        raise ValueError("unknown ciphertext version")
    nonce, ct = raw[2:14], raw[14:]
    return AESGCM(key).decrypt(nonce, ct, aad.encode()).decode()


def blind_index(value: str, key: bytes) -> str:
    """Deterministic keyed hash so we can look up / dedupe a payee without storing it in clear."""
    return hmac.new(key, value.strip().lower().encode(), hashlib.sha256).hexdigest()


def mask_email(email: str) -> str:
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    head = local[:1]
    return f"{head}{'*' * max(len(local) - 1, 2)}@{domain}"

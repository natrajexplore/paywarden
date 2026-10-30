"""HTTP hardening: security headers, request IDs, body-size cap, rate limiting per IP and per
credential.

Controls mapped: OWASP ASVS v4 V14 (config / headers), V13.1.3 (request size), PCI DSS 6.4 (protect
public-facing web apps), NIST SP 800-53 SC-5 (DoS protection), SC-8 (transmission confidentiality
via HSTS), AU-3 (request correlation IDs, sanitised against log forging).

Client IP: behind a proxy, run uvicorn with --proxy-headers and FORWARDED_ALLOW_IPS set to the
proxy's address so request.client reflects the real client, not a spoofable header.
"""
from __future__ import annotations

import hashlib
import re
import time
import uuid
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
# FastAPI's Swagger UI (/docs) needs its CDN assets and one inline bootstrap script.
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'none'"
)


_RID = re.compile(r"^[A-Za-z0-9-]{8,64}$")


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id", "")
        if not _RID.match(rid):  # never echo attacker-controlled bytes into headers/logs
            rid = uuid.uuid4().hex
        request.state.request_id = rid
        response = await call_next(request)
        response.headers.update({
            "X-Request-ID": rid,
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy": DOCS_CSP if request.url.path in ("/docs", "/redoc") else CSP,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-Permitted-Cross-Domain-Policies": "none",
            "Cache-Control": "no-store",
        })
        return response


class BodySizeLimit(BaseHTTPMiddleware):
    """Reject oversized or unsized request bodies before they are read."""
    def __init__(self, app, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            length = request.headers.get("content-length")
            if length is None:
                if "chunked" in request.headers.get("transfer-encoding", "").lower():
                    return JSONResponse({"detail": "content-length required"}, status_code=411)
            elif not length.isdigit() or int(length) > self.max_bytes:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)


class RateLimit(BaseHTTPMiddleware):
    """Sliding 60s window. A request must pass both its IP bucket and, if it carries a credential,
    that credential's bucket — so a stolen token is throttled even when spread across IPs."""
    def __init__(self, app, per_minute: int = 120):
        super().__init__(app)
        self.per_minute = per_minute
        self.hits: dict[str, deque] = defaultdict(deque)

    def _keys(self, request: Request) -> list[str]:
        keys = ["ip:" + (request.client.host if request.client else "unknown")]
        auth = request.headers.get("authorization", "")
        if auth:
            keys.append("cred:" + hashlib.sha256(auth.encode()).hexdigest()[:24])
        return keys

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/"):
            now = time.time()
            if len(self.hits) > 10000:  # bound memory: drop idle buckets
                for k in [k for k, q in self.hits.items() if not q or now - q[-1] > 60]:
                    del self.hits[k]
            buckets = [self.hits[k] for k in self._keys(request)]
            for q in buckets:
                while q and now - q[0] > 60:
                    q.popleft()
            if any(len(q) >= self.per_minute for q in buckets):
                return JSONResponse({"detail": "rate limit exceeded"}, status_code=429,
                                    headers={"Retry-After": "60"})
            for q in buckets:
                q.append(now)
        return await call_next(request)

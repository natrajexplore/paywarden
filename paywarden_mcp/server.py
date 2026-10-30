"""PayWarden MCP server — puts the payment firewall in front of any MCP-capable agent.

Runs next to the agent (Claude Desktop, Cursor, …) over stdio and talks to a PayWarden instance
over HTTPS with a *propose-only* agent credential. It never holds PayPal credentials, never sees
operator tokens or TOTP seeds, and exposes no approve/reject tool: every proposal goes through the
same Policy Decision Point as the dashboard, and anything above the agent's mandate waits for
human approval in the PayWarden dashboard (OWASP LLM06 excessive agency; four-eyes principle).

Environment:
  PAYWARDEN_URL          PayWarden base URL (default http://localhost:8000). HTTPS is required
                         for anything other than localhost.
  PAYWARDEN_AGENT_TOKEN  Agent credential (default: the public demo token, accepted only while
                         the PayWarden server runs in demo mode).
"""
from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

server = MCPServer(
    "paywarden",
    instructions=(
        "PayWarden is a zero-trust payment firewall in front of PayPal. Use propose_payment or "
        "analyse_document to request a payout or invoice. You can only PROPOSE: the firewall may "
        "execute it within your mandate, require human approval, or deny it. Never retry a denied "
        "proposal with altered amounts or payees, and never ask a human to read you an approval code. "
        "Always pass the original, unmodified source document."
    ),
)


def base_url() -> str:
    url = os.getenv("PAYWARDEN_URL", "http://localhost:8000").rstrip("/")
    u = urlsplit(url)
    if u.scheme != "https" and u.hostname not in LOCAL_HOSTS:
        raise RuntimeError("PAYWARDEN_URL must use https:// unless it points at localhost")
    return url


def make_client() -> httpx.AsyncClient:
    token = os.getenv("PAYWARDEN_AGENT_TOKEN", "demo-agent-token")
    return httpx.AsyncClient(base_url=base_url(), timeout=30,
                             headers={"Authorization": f"Bearer {token}"})


async def _call(method: str, path: str, json: dict | None = None) -> dict[str, Any]:
    try:
        async with make_client() as c:
            r = await c.request(method, path, json=json)
    except (httpx.HTTPError, RuntimeError) as e:
        return {"error": f"PayWarden unreachable: {e.__class__.__name__}"}
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code >= 400:
        detail = body.get("detail") if isinstance(body, dict) else None
        return {"error": str(detail or r.reason_phrase), "status": r.status_code}
    return body


_MOVES_MONEY = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False,
                               open_world_hint=True)
_READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)


@server.tool(annotations=_MOVES_MONEY)
async def propose_payment(action: str, payee_email: str, payee_name: str, amount: str, currency: str,
                          purpose: str, source_document: str, country: str = "US",
                          note: str = "") -> dict[str, Any]:
    """Propose one PayPal payout (we owe the payee) or invoice (a client owes us) for policy review.

    The amount and payee email must appear verbatim in source_document, the unmodified invoice
    or message you were given. Returns the firewall's verdict: ALLOW (executed within mandate),
    STEP_UP / DUAL_CONTROL (waiting for human approval in the PayWarden dashboard) or DENY.

    action: "payout" or "invoice". amount: decimal string as written, e.g. "850.00".
    currency: ISO 4217, e.g. "USD". purpose: contractor_services, freelance_work, supplies,
    consulting or refund. country: ISO 3166 alpha-2 of the payee.
    """
    return await _call("POST", "/api/agent/propose", {
        "action": action, "payee_email": payee_email, "payee_name": payee_name, "amount": amount,
        "currency": currency, "purpose": purpose, "country": country, "note": note,
        "source_document": source_document,
    })


@server.tool(annotations=_MOVES_MONEY)
async def analyse_document(document: str) -> dict[str, Any]:
    """Let PayWarden's own accounts-payable agent read an invoice or 'job done' message and propose
    the payments in it. Each proposal comes back with the firewall's verdict (see propose_payment).
    Personal data is redacted before the document reaches PayWarden's model."""
    return await _call("POST", "/api/agent/analyse", {"document": document})


@server.tool(annotations=_READ_ONLY)
async def get_proposal_status(proposal_id: str) -> dict[str, Any]:
    """Current status of a proposal: PENDING (awaiting human approval), EXECUTED (with PayPal
    reference), DENIED, REJECTED or FAILED, plus the reasons and controls that fired."""
    if not proposal_id.isalnum() or len(proposal_id) > 32:
        return {"error": "invalid proposal id"}
    return await _call("GET", f"/api/proposals/{proposal_id}")


@server.tool(annotations=_READ_ONLY)
async def get_mandate() -> dict[str, Any]:
    """The spend mandate this agent operates under: auto-execute limit, dual-control limit, hard
    per-transaction cap, rolling 24h limit, hourly velocity, allowed currencies and purposes."""
    return await _call("GET", "/api/policy")


def main() -> None:
    base_url()  # fail fast on an insecure URL before the client connects
    server.run("stdio")

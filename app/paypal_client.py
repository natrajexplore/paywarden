"""PayPal REST client (SANDBOX). Only PayWarden holds these credentials — never the AI agent.

Products used: OAuth 2.0, Payouts (v1), Invoicing (v2), Orders (v2), Webhooks (signature verify).
Security:
  * TLS 1.2+ with certificate verification (httpx default) — PCI DSS 4.2.1
  * OAuth2 client-credentials, token cached in memory only, refreshed before expiry
  * PayPal-Request-Id idempotency on every write -> no double payouts on retry
  * Timeouts + bounded retries on 5xx/429 only
When no credentials are configured, a deterministic MOCK backend returns sandbox-shaped responses
so judges can run the full flow with zero setup.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

import httpx

from .config import settings


class PayPalError(Exception):
    def __init__(self, status: int, body: Any):
        super().__init__(f"PayPal API error {status}: {body}")
        self.status = status
        self.body = body


class PayPalClient:
    def __init__(self) -> None:
        self.base = settings.paypal_base_url.rstrip("/")
        self.live = settings.paypal_live
        self._token: str | None = None
        self._token_exp = 0.0
        self._lock = asyncio.Lock()
        self._mock_orders: dict[str, dict] = {}

    @property
    def mode(self) -> str:
        return "sandbox" if self.live else "mock"

    async def _access_token(self) -> str:
        async with self._lock:
            if self._token and time.time() < self._token_exp - 60:
                return self._token
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.post(
                    f"{self.base}/v1/oauth2/token",
                    data={"grant_type": "client_credentials"},
                    auth=(settings.paypal_client_id or "", settings.paypal_client_secret or ""),
                    headers={"Accept": "application/json"},
                )
            if r.status_code != 200:
                raise PayPalError(r.status_code, r.text[:300])
            data = r.json()
            self._token = data["access_token"]
            self._token_exp = time.time() + int(data.get("expires_in", 3000))
            return self._token

    async def _call(self, method: str, path: str, json: dict | None = None,
                    request_id: str | None = None) -> dict:
        token = await self._access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                   "Prefer": "return=representation"}
        if request_id:
            headers["PayPal-Request-Id"] = request_id
        last: Exception | None = None
        for attempt in range(3):
            async with httpx.AsyncClient(timeout=20) as c:
                r = await c.request(method, f"{self.base}{path}", json=json, headers=headers)
            if r.status_code < 300:
                return r.json() if r.content else {}
            if r.status_code in (429, 500, 502, 503, 504):
                last = PayPalError(r.status_code, r.text[:300])
                await asyncio.sleep(0.5 * (2 ** attempt))
                continue
            raise PayPalError(r.status_code, r.json() if r.content else {})
        raise last  # type: ignore[misc]

    # ---- Payouts --------------------------------------------------------
    async def create_payout(self, proposal_id: str, email: str, amount: str, currency: str,
                            note: str) -> dict:
        body = {
            "sender_batch_header": {
                "sender_batch_id": f"pw-{proposal_id}",
                "email_subject": "You have a payment",
                "email_message": "Payment approved via PayWarden.",
            },
            "items": [{
                "recipient_type": "EMAIL",
                "amount": {"value": amount, "currency": currency},
                "receiver": email,
                "note": note[:4000] or "Payment",
                "sender_item_id": proposal_id,
            }],
        }
        if not self.live:
            return {"batch_header": {"payout_batch_id": f"MOCK-{uuid.uuid4().hex[:12].upper()}",
                                     "batch_status": "PENDING",
                                     "sender_batch_header": body["sender_batch_header"]},
                    "mock": True}
        return await self._call("POST", "/v1/payments/payouts", body, request_id=f"payout-{proposal_id}")

    async def get_payout(self, batch_id: str) -> dict:
        if not self.live:
            return {"batch_header": {"payout_batch_id": batch_id, "batch_status": "SUCCESS"}, "mock": True}
        return await self._call("GET", f"/v1/payments/payouts/{batch_id}")

    # ---- Invoicing ------------------------------------------------------
    async def create_and_send_invoice(self, proposal_id: str, email: str, name: str, amount: str,
                                      currency: str, description: str) -> dict:
        body = {
            "detail": {"currency_code": currency, "note": "Issued via PayWarden",
                       "reference": proposal_id[:20]},
            "primary_recipients": [{"billing_info": {"email_address": email,
                                                     "name": {"full_name": name[:140]}}}],
            "items": [{"name": (description or "Services")[:200], "quantity": "1",
                       "unit_amount": {"currency_code": currency, "value": amount}}],
        }
        if not self.live:
            return {"id": f"INV2-MOCK-{uuid.uuid4().hex[:8].upper()}", "status": "SENT", "mock": True}
        inv = await self._call("POST", "/v2/invoicing/invoices", body, request_id=f"inv-{proposal_id}")
        inv_id = inv.get("id") or inv.get("href", "").rsplit("/", 1)[-1]
        await self._call("POST", f"/v2/invoicing/invoices/{inv_id}/send",
                         {"send_to_recipient": True}, request_id=f"inv-send-{proposal_id}")
        return {"id": inv_id, "status": "SENT"}

    # ---- Orders (agent-to-agent settlement) -----------------------------
    # Mock mode keeps orders in memory and simulates the payer's approval (status APPROVED).
    async def create_order(self, ref: str, amount: str, currency: str, description: str,
                           payee_email: str | None = None) -> dict:
        unit = {"reference_id": ref[:256], "description": description[:127],
                "amount": {"currency_code": currency, "value": amount}}
        if payee_email:
            unit["payee"] = {"email_address": payee_email}
        body = {"intent": "CAPTURE", "purchase_units": [unit]}
        if not self.live:
            oid = f"MOCK-ORDER-{uuid.uuid4().hex[:10].upper()}"
            self._mock_orders[oid] = {"id": oid, "status": "APPROVED", "purchase_units": [unit], "links": [],
                                      "mock": True}
            return self._mock_orders[oid]
        return await self._call("POST", "/v2/checkout/orders", body, request_id=f"order-{ref}")

    async def get_order(self, order_id: str) -> dict:
        if not self.live:
            if order_id not in self._mock_orders:
                raise PayPalError(404, {"name": "RESOURCE_NOT_FOUND"})
            return self._mock_orders[order_id]
        return await self._call("GET", f"/v2/checkout/orders/{order_id}")

    async def capture_order(self, order_id: str, proposal_id: str) -> dict:
        if not self.live:
            order = self._mock_orders[order_id]
            order["status"] = "COMPLETED"
            return {"id": order_id, "status": "COMPLETED", "purchase_units": [{"payments": {"captures": [
                {"id": f"MOCK-CAPTURE-{uuid.uuid4().hex[:10].upper()}", "status": "COMPLETED"}]}}], "mock": True}
        return await self._call("POST", f"/v2/checkout/orders/{order_id}/capture", {},
                                request_id=f"capture-{proposal_id}")

    # ---- Webhooks -------------------------------------------------------
    async def verify_webhook(self, headers: dict, event: dict) -> bool:
        """Server-side verification via PayPal's verify-webhook-signature endpoint."""
        if not self.live or not settings.paypal_webhook_id:
            return False
        h = {k.lower(): v for k, v in headers.items()}
        body = {
            "auth_algo": h.get("paypal-auth-algo"),
            "cert_url": h.get("paypal-cert-url"),
            "transmission_id": h.get("paypal-transmission-id"),
            "transmission_sig": h.get("paypal-transmission-sig"),
            "transmission_time": h.get("paypal-transmission-time"),
            "webhook_id": settings.paypal_webhook_id,
            "webhook_event": event,
        }
        if not all(body.values()):
            return False
        res = await self._call("POST", "/v1/notifications/verify-webhook-signature", body)
        return res.get("verification_status") == "SUCCESS"


paypal = PayPalClient()

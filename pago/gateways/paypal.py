"""
Adaptador PayPal (Checkout / Orders API v2).

Flujo de ORDEN (no de token de tarjeta): el navegador renderiza los botones del
SDK JS de PayPal; el servidor crea la orden (create_order), el pagador la
aprueba en la ventana de PayPal y el servidor la captura (capture_order).
El dinero cae en el saldo PayPal Business de la empresa.

PCI-DSS: la tarjeta la maneja PayPal de punta a punta; a este servidor solo
llegan ids de orden/captura.

Config (.env):
  GATEWAY=paypal
  PAYPAL_ENV=live|sandbox
  PAYPAL_CLIENT_ID=...      (publico: se incrusta en la pagina de pago)
  PAYPAL_CLIENT_SECRET=...  (secreto)
  PAYPAL_WEBHOOK_ID=...     (opcional: para verificar webhooks)
"""
import logging
import os
import threading
import time

import requests

from .base import GatewayError, GatewayResult, WebhookEvent

log = logging.getLogger("dimed-pago.paypal")

_token_lock = threading.Lock()
_token_cache = {}   # (base, client_id) -> (access_token, expira_epoch)

_TIMEOUT = (10, 30)


class PayPalGateway:
    name = "paypal"
    supports_orders = True   # flujo orden/captura (SDK JS), no card_token

    def __init__(self):
        env = (os.environ.get("PAYPAL_ENV") or "sandbox").strip().lower()
        self.base = ("https://api-m.paypal.com" if env == "live"
                     else "https://api-m.sandbox.paypal.com")
        self.client_id = os.environ.get("PAYPAL_CLIENT_ID", "")
        self.secret = os.environ.get("PAYPAL_CLIENT_SECRET", "")
        self.webhook_id = os.environ.get("PAYPAL_WEBHOOK_ID", "")
        if not self.client_id or not self.secret:
            raise GatewayError("PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET no configurados")

    # -- HTTP ---------------------------------------------------------------
    def _auth_token(self):
        key = (self.base, self.client_id)
        with _token_lock:
            tok = _token_cache.get(key)
            if tok and tok[1] > time.time() + 60:
                return tok[0]
        try:
            r = requests.post(f"{self.base}/v1/oauth2/token",
                              auth=(self.client_id, self.secret),
                              data={"grant_type": "client_credentials"},
                              timeout=_TIMEOUT)
        except requests.RequestException as e:
            raise GatewayError(f"PayPal no responde (oauth): {e.__class__.__name__}")
        if r.status_code != 200:
            raise GatewayError(f"PayPal rechazo las credenciales (HTTP {r.status_code})")
        d = r.json()
        with _token_lock:
            _token_cache[key] = (d["access_token"], time.time() + int(d.get("expires_in", 300)))
        return d["access_token"]

    def _req(self, method, path, body=None):
        headers = {"Authorization": f"Bearer {self._auth_token()}",
                   "Content-Type": "application/json"}
        try:
            r = requests.request(method, f"{self.base}{path}", json=body,
                                 headers=headers, timeout=_TIMEOUT)
        except requests.RequestException as e:
            raise GatewayError(f"PayPal no responde: {e.__class__.__name__}")
        if r.status_code >= 500:
            raise GatewayError(f"Error interno de PayPal (HTTP {r.status_code})")
        try:
            data = r.json() if r.content else {}
        except ValueError:
            data = {}
        return r.status_code, data

    # -- Contrato -----------------------------------------------------------
    def create_order(self, *, amount, currency, description, reference):
        """Crea la orden que el SDK JS le presenta al pagador."""
        status, d = self._req("POST", "/v2/checkout/orders", {
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": str(reference)[:127],
                "description": (description or "")[:127],
                "amount": {"currency_code": currency, "value": f"{amount:.2f}"},
            }],
        })
        if status not in (200, 201) or not d.get("id"):
            raise GatewayError(f"PayPal no creo la orden (HTTP {status}): "
                               f"{d.get('message') or d.get('name') or ''}")
        return GatewayResult(ok=True, status="iniciado", gateway_ref=d["id"],
                             raw_status=d.get("status", "CREATED"))

    def capture_order(self, order_id):
        """Captura una orden aprobada por el pagador. El id de CAPTURA (para
        reembolsos) va en extra['capture_id']."""
        status, d = self._req("POST", f"/v2/checkout/orders/{order_id}/capture")
        if status == 422:
            issue = (d.get("details") or [{}])[0].get("issue", "")
            if issue == "INSTRUMENT_DECLINED":
                # el pagador puede reintentar con otro medio (actions.restart())
                return GatewayResult(ok=False, status="rechazado", gateway_ref=order_id,
                                     raw_status=issue,
                                     message="PayPal rechazo el medio de pago. Intente con otro.",
                                     extra={"retry": True})
            if issue == "ORDER_ALREADY_CAPTURED":
                return self.confirm(order_id)
            return GatewayResult(ok=False, status="rechazado", gateway_ref=order_id,
                                 raw_status=issue or "UNPROCESSABLE",
                                 message=d.get("message") or "PayPal no proceso el pago")
        if status not in (200, 201):
            raise GatewayError(f"PayPal no capturo la orden (HTTP {status}): "
                               f"{d.get('message') or d.get('name') or ''}")
        return self._parse_capture_response(order_id, d)

    def _parse_capture_response(self, order_id, d):
        caps = []
        for pu in d.get("purchase_units", []):
            caps += (pu.get("payments") or {}).get("captures") or []
        cap = caps[0] if caps else {}
        completed = d.get("status") == "COMPLETED" and cap.get("status") in ("COMPLETED", "PENDING")
        card = (d.get("payment_source") or {}).get("card") or {}
        payer = d.get("payer") or {}
        return GatewayResult(
            ok=completed,
            status="aprobado" if completed else "rechazado",
            gateway_ref=order_id,
            raw_status=cap.get("status") or d.get("status", ""),
            message="" if completed else "PayPal no completo el pago",
            card_brand=(card.get("brand") or "paypal").lower(),
            card_last4=card.get("last_digits", ""),
            extra={"capture_id": cap.get("id", ""),
                   "payer_email": payer.get("email_address", "")},
        )

    def confirm(self, gateway_ref):
        status, d = self._req("GET", f"/v2/checkout/orders/{gateway_ref}")
        if status != 200:
            raise GatewayError(f"PayPal no devolvio la orden (HTTP {status})")
        return self._parse_capture_response(gateway_ref, d)

    def refund(self, gateway_ref, amount=None):
        """gateway_ref debe ser el id de CAPTURA (gateway_capture_ref)."""
        body = {}
        if amount is not None:
            body = {"amount": {"value": f"{amount:.2f}", "currency_code": "USD"}}
        status, d = self._req("POST", f"/v2/payments/captures/{gateway_ref}/refund", body)
        if status in (200, 201) and d.get("status") in ("COMPLETED", "PENDING"):
            return GatewayResult(ok=True, status="reembolsado", gateway_ref=d.get("id", ""),
                                 raw_status=d.get("status", ""))
        return GatewayResult(ok=False, status="rechazado", gateway_ref=gateway_ref,
                             raw_status=d.get("status", str(status)),
                             message=d.get("message") or "PayPal rechazo el reembolso")

    def create_charge(self, **kwargs):
        raise NotImplementedError("PayPal usa flujo de orden: create_order + capture_order")

    def parse_webhook(self, headers, body):
        """Verifica la firma contra la API de PayPal (requiere PAYPAL_WEBHOOK_ID)."""
        import json
        if not self.webhook_id:
            raise ValueError("PAYPAL_WEBHOOK_ID no configurado")
        try:
            event = json.loads(body)
        except ValueError:
            raise ValueError("cuerpo no es JSON")
        h = {k.lower(): v for k, v in headers.items()}
        status, d = self._req("POST", "/v1/notifications/verify-webhook-signature", {
            "transmission_id": h.get("paypal-transmission-id", ""),
            "transmission_time": h.get("paypal-transmission-time", ""),
            "cert_url": h.get("paypal-cert-url", ""),
            "auth_algo": h.get("paypal-auth-algo", ""),
            "transmission_sig": h.get("paypal-transmission-sig", ""),
            "webhook_id": self.webhook_id,
            "webhook_event": event,
        })
        if status != 200 or d.get("verification_status") != "SUCCESS":
            raise ValueError("firma de webhook invalida")
        etype = event.get("event_type", "")
        resource = event.get("resource") or {}
        order_id = ((resource.get("supplementary_data") or {})
                    .get("related_ids") or {}).get("order_id") or resource.get("id", "")
        mapping = {"PAYMENT.CAPTURE.COMPLETED": "aprobado",
                   "PAYMENT.CAPTURE.DENIED": "rechazado",
                   "PAYMENT.CAPTURE.REFUNDED": "reembolsado"}
        return WebhookEvent(gateway=self.name, event_type=etype,
                            external_id=event.get("id", ""), gateway_ref=order_id,
                            status=mapping.get(etype, "iniciado"), payload=event)

"""
Pasarela SIMULADA para probar el flujo completo sin cuenta de comercio ni
dinero real. Determinista y sin estado: el resultado lo decide el card_token
(tok_ok / tok_rechazada / tok_fondos / tok_error) o, en su defecto, los
centavos del monto (.00 aprobado, .01 rechazada, .02 fondos, .03 error).
"""
import secrets
from decimal import Decimal

from .base import GatewayError, GatewayResult


class SandboxGateway:
    name = "sandbox"

    _TOKEN_OUTCOMES = {
        "tok_ok": ("aprobado", ""),
        "tok_rechazada": ("rechazado", "Tarjeta rechazada por el emisor"),
        "tok_fondos": ("rechazado", "Fondos insuficientes"),
    }
    _CENT_OUTCOMES = {0: "ok", 1: "rechazada", 2: "fondos", 3: "error"}

    def _outcome(self, card_token, amount):
        if card_token in self._TOKEN_OUTCOMES or card_token == "tok_error":
            return card_token
        cents = int((Decimal(amount) * 100) % 100)
        return "tok_" + self._CENT_OUTCOMES.get(cents, "ok")

    def create_charge(self, *, amount, currency, card_token, description,
                      payer_email, installments=None, metadata=None):
        outcome = self._outcome(card_token, amount)
        if outcome == "tok_error":
            raise GatewayError("Sandbox: error simulado de comunicacion con la pasarela")
        status, message = self._TOKEN_OUTCOMES[outcome]
        return GatewayResult(
            ok=(status == "aprobado"),
            status=status,
            gateway_ref="sbx_" + secrets.token_hex(10),
            raw_status="APPROVED" if status == "aprobado" else "DECLINED",
            message=message,
            card_brand="visa" if status == "aprobado" else "",
            card_last4="4242" if status == "aprobado" else "",
        )

    def confirm(self, gateway_ref):
        # Sandbox no tiene captura diferida: eco de aprobado.
        return GatewayResult(ok=True, status="aprobado", gateway_ref=gateway_ref,
                             raw_status="APPROVED")

    def refund(self, gateway_ref, amount=None):
        # La app valida contra la BD que el pago exista y este 'aprobado'.
        return GatewayResult(ok=True, status="reembolsado",
                             gateway_ref="sbx_re_" + secrets.token_hex(10),
                             raw_status="REFUNDED",
                             extra={"original_ref": gateway_ref})

    def parse_webhook(self, headers, body):
        raise NotImplementedError("Sandbox no emite webhooks")

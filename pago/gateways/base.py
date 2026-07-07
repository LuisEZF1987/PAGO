"""
Contrato de las pasarelas de tarjeta (adaptadores pluggable).

PCI-DSS: el servidor JAMAS recibe ni guarda PAN/CVV. La tokenizacion de la
tarjeta ocurre en el navegador con el SDK del gateway; aqui solo llega el
`card_token` opaco y se persisten `gateway_ref`, `card_brand` y `card_last4`
(datos permitidos). Cualquier adaptador nuevo (Kushki, PayPal, ...) implementa
este Protocol y se registra en gateways/__init__.py — el core no cambia.
"""
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Protocol


class GatewayError(Exception):
    """Fallo de comunicacion/operacion con la pasarela (no un rechazo de tarjeta)."""


@dataclass
class GatewayResult:
    ok: bool
    status: str              # normalizado: 'aprobado' | 'rechazado' | 'iniciado' | 'reembolsado'
    gateway_ref: str = ""    # id de la transaccion en la pasarela
    raw_status: str = ""     # estado crudo que devolvio la pasarela
    message: str = ""        # motivo legible ('Fondos insuficientes', ...)
    card_brand: str = ""
    card_last4: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class WebhookEvent:
    gateway: str
    event_type: str          # 'charge.approved' | 'charge.declined' | 'refund.completed'
    external_id: str         # id del evento (idempotencia via pago_gateway_events)
    gateway_ref: str
    status: str              # ya mapeado a estado interno
    payload: dict


class PaymentGateway(Protocol):
    name: str

    def create_charge(self, *, amount: Decimal, currency: str, card_token: str,
                      description: str, payer_email: str,
                      installments: int | None = None,
                      metadata: dict | None = None) -> GatewayResult:
        """Cobra la tarjeta tokenizada. Rechazo => ok=False (no excepcion);
        GatewayError solo para fallos de comunicacion."""
        ...

    def confirm(self, gateway_ref: str) -> GatewayResult:
        """Consulta/captura diferida de una transaccion existente."""
        ...

    def refund(self, gateway_ref: str, amount: Decimal | None = None) -> GatewayResult:
        """Reembolsa (total si amount es None)."""
        ...

    def parse_webhook(self, headers: dict, body: bytes) -> WebhookEvent:
        """Valida la firma del webhook y lo normaliza. ValueError si es invalido."""
        ...

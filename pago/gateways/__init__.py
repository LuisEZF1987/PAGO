"""Registro de pasarelas. Para agregar una real: crear el modulo (p.ej.
kushki.py con class KushkiGateway) y sumarla a _REGISTRY; nada mas cambia."""
import os

from .base import GatewayError, GatewayResult, PaymentGateway, WebhookEvent  # noqa: F401
from .paypal import PayPalGateway
from .sandbox import SandboxGateway

_REGISTRY = {
    "sandbox": SandboxGateway,
    "paypal": PayPalGateway,
    # "kushki": KushkiGateway,   # cuando haya cuenta con procesador local (diferidos)
}


def get_gateway(name=None):
    name = (name or os.environ.get("GATEWAY", "sandbox")).strip().lower()
    try:
        return _REGISTRY[name]()
    except KeyError:
        raise RuntimeError(f"Gateway no soportado: {name}")


def known_gateway(name):
    return name in _REGISTRY

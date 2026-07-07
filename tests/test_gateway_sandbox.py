"""SandboxGateway: resultados deterministas y contrato del adaptador."""
from decimal import Decimal

import pytest

from gateways import GatewayError, get_gateway
from gateways.sandbox import SandboxGateway


def _charge(gw, token="tok_ok", amount="100.00"):
    return gw.create_charge(amount=Decimal(amount), currency="USD", card_token=token,
                            description="test", payer_email="a@b.c")


class TestOutcomes:
    def test_aprobada(self):
        res = _charge(SandboxGateway(), "tok_ok")
        assert res.ok and res.status == "aprobado"
        assert res.gateway_ref.startswith("sbx_")
        assert res.card_last4 == "4242"

    def test_rechazada(self):
        res = _charge(SandboxGateway(), "tok_rechazada")
        assert not res.ok and res.status == "rechazado"
        assert "emisor" in res.message

    def test_fondos(self):
        res = _charge(SandboxGateway(), "tok_fondos")
        assert not res.ok and "Fondos" in res.message

    def test_error_comunicacion(self):
        with pytest.raises(GatewayError):
            _charge(SandboxGateway(), "tok_error")

    def test_por_centavos(self):
        gw = SandboxGateway()
        assert _charge(gw, "tok_x", "50.00").ok
        assert not _charge(gw, "tok_x", "50.01").ok
        assert "Fondos" in _charge(gw, "tok_x", "50.02").message
        with pytest.raises(GatewayError):
            _charge(gw, "tok_x", "50.03")


class TestRefund:
    def test_refund(self):
        res = SandboxGateway().refund("sbx_abc123")
        assert res.ok and res.status == "reembolsado"
        assert res.gateway_ref.startswith("sbx_re_")
        assert res.extra["original_ref"] == "sbx_abc123"


class TestRegistry:
    def test_default_sandbox(self):
        assert get_gateway().name == "sandbox"

    def test_desconocido(self):
        with pytest.raises(RuntimeError):
            get_gateway("noexiste")

    def test_sandbox_no_webhooks(self):
        with pytest.raises(NotImplementedError):
            SandboxGateway().parse_webhook({}, b"{}")

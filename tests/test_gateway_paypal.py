"""PayPalGateway: mapeo de la API de ordenes/capturas SIN tocar la red (HTTP simulado)."""
from decimal import Decimal

import pytest

import gateways.paypal as pp
from gateways.base import GatewayError


class FakeResp:
    def __init__(self, status_code, data):
        self.status_code = status_code
        self._data = data
        self.content = b"x"

    def json(self):
        return self._data


class FakeRequests:
    """Sustituto del modulo requests: respuestas encoladas por (metodo, sufijo de ruta)."""

    RequestException = Exception

    def __init__(self):
        self.routes = {}
        self.calls = []

    def add(self, method, path_suffix, status, data):
        self.routes[(method.upper(), path_suffix)] = (status, data)

    def _find(self, method, url):
        for (m, suffix), resp in self.routes.items():
            if m == method.upper() and url.endswith(suffix):
                return resp
        raise AssertionError(f"sin ruta simulada para {method} {url}")

    def post(self, url, **kw):
        self.calls.append(("POST", url))
        return FakeResp(*self._find("POST", url))

    def request(self, method, url, **kw):
        self.calls.append((method, url))
        return FakeResp(*self._find(method, url))


@pytest.fixture
def fake(monkeypatch):
    f = FakeRequests()
    f.add("POST", "/v1/oauth2/token", 200, {"access_token": "tok123", "expires_in": 3600})
    monkeypatch.setattr(pp, "requests", f)
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "cid")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "sec")
    monkeypatch.setenv("PAYPAL_ENV", "sandbox")
    pp._token_cache.clear()
    return f


def test_sin_credenciales_falla(monkeypatch):
    monkeypatch.delenv("PAYPAL_CLIENT_ID", raising=False)
    monkeypatch.delenv("PAYPAL_CLIENT_SECRET", raising=False)
    with pytest.raises(GatewayError):
        pp.PayPalGateway()


def test_create_order(fake):
    fake.add("POST", "/v2/checkout/orders", 201, {"id": "ORD-1", "status": "CREATED"})
    res = pp.PayPalGateway().create_order(amount=Decimal("150.00"), currency="USD",
                                          description="Equipo", reference="pid-1")
    assert res.ok and res.gateway_ref == "ORD-1" and res.status == "iniciado"


def test_oauth_invalido(fake):
    fake.add("POST", "/v1/oauth2/token", 401, {"error": "invalid_client"})
    with pytest.raises(GatewayError):
        pp.PayPalGateway().create_order(amount=Decimal("1.00"), currency="USD",
                                        description="x", reference="r")


def test_token_se_cachea(fake):
    fake.add("POST", "/v2/checkout/orders", 201, {"id": "ORD-1", "status": "CREATED"})
    gw = pp.PayPalGateway()
    gw.create_order(amount=Decimal("1.00"), currency="USD", description="x", reference="a")
    gw.create_order(amount=Decimal("2.00"), currency="USD", description="x", reference="b")
    oauth_calls = [c for c in fake.calls if c[1].endswith("/v1/oauth2/token")]
    assert len(oauth_calls) == 1


def test_capture_completed(fake):
    fake.add("POST", "/v2/checkout/orders/ORD-1/capture", 201, {
        "status": "COMPLETED",
        "payer": {"email_address": "cliente@mail.com"},
        "payment_source": {"card": {"brand": "VISA", "last_digits": "1111"}},
        "purchase_units": [{"payments": {"captures": [{"id": "CAP-9", "status": "COMPLETED"}]}}],
    })
    res = pp.PayPalGateway().capture_order("ORD-1")
    assert res.ok and res.status == "aprobado"
    assert res.extra["capture_id"] == "CAP-9"
    assert res.card_brand == "visa" and res.card_last4 == "1111"
    assert res.extra["payer_email"] == "cliente@mail.com"


def test_capture_cuenta_paypal_sin_tarjeta(fake):
    fake.add("POST", "/v2/checkout/orders/ORD-2/capture", 201, {
        "status": "COMPLETED", "payer": {"email_address": "p@x.com"},
        "payment_source": {"paypal": {}},
        "purchase_units": [{"payments": {"captures": [{"id": "CAP-2", "status": "COMPLETED"}]}}],
    })
    res = pp.PayPalGateway().capture_order("ORD-2")
    assert res.ok and res.card_brand == "paypal" and res.card_last4 == ""


def test_capture_instrument_declined_permite_reintento(fake):
    fake.add("POST", "/v2/checkout/orders/ORD-3/capture", 422,
             {"details": [{"issue": "INSTRUMENT_DECLINED"}]})
    res = pp.PayPalGateway().capture_order("ORD-3")
    assert not res.ok and res.status == "rechazado"
    assert res.extra.get("retry") is True


def test_capture_error_5xx(fake):
    fake.add("POST", "/v2/checkout/orders/ORD-4/capture", 500, {})
    with pytest.raises(GatewayError):
        pp.PayPalGateway().capture_order("ORD-4")


def test_refund(fake):
    fake.add("POST", "/v2/payments/captures/CAP-9/refund", 201,
             {"id": "REF-1", "status": "COMPLETED"})
    res = pp.PayPalGateway().refund("CAP-9")
    assert res.ok and res.status == "reembolsado" and res.gateway_ref == "REF-1"


def test_webhook_sin_id_configurado(fake):
    with pytest.raises(ValueError):
        pp.PayPalGateway().parse_webhook({}, b"{}")


def test_webhook_verificado(fake, monkeypatch):
    monkeypatch.setenv("PAYPAL_WEBHOOK_ID", "WH-1")
    fake.add("POST", "/v1/notifications/verify-webhook-signature", 200,
             {"verification_status": "SUCCESS"})
    body = (b'{"id":"EV-1","event_type":"PAYMENT.CAPTURE.COMPLETED",'
            b'"resource":{"id":"CAP-9","supplementary_data":{"related_ids":{"order_id":"ORD-1"}}}}')
    ev = pp.PayPalGateway().parse_webhook({"Paypal-Transmission-Id": "t"}, body)
    assert ev.status == "aprobado" and ev.gateway_ref == "ORD-1" and ev.external_id == "EV-1"


def test_webhook_firma_invalida(fake, monkeypatch):
    monkeypatch.setenv("PAYPAL_WEBHOOK_ID", "WH-1")
    fake.add("POST", "/v1/notifications/verify-webhook-signature", 200,
             {"verification_status": "FAILURE"})
    with pytest.raises(ValueError):
        pp.PayPalGateway().parse_webhook({}, b'{"id":"EV-2"}')

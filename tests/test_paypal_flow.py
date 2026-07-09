"""Flujo publico PayPal (orden → captura) con gateway simulado y BD real."""
from decimal import Decimal

import pytest

import pago_app
from gateways.base import GatewayResult

pytestmark = pytest.mark.db


class FakeOrdersGateway:
    """Simula un gateway de flujo orden/captura (como PayPal), controlable por test."""
    name = "paypal"
    supports_orders = True

    def __init__(self):
        self.capture_result = "ok"
        self.refunded = []
        self._orders = {}  # order_id -> (amount, currency), para simular la captura real

    def create_order(self, *, amount, currency, description, reference):
        self._orders["FAKE-ORD-1"] = (Decimal(str(amount)), currency)
        return GatewayResult(ok=True, status="iniciado", gateway_ref="FAKE-ORD-1",
                             raw_status="CREATED")

    def capture_order(self, order_id):
        if self.capture_result == "retry":
            return GatewayResult(ok=False, status="rechazado", gateway_ref=order_id,
                                 raw_status="INSTRUMENT_DECLINED",
                                 message="medio rechazado", extra={"retry": True})
        amt, cur_ = self._orders.get(order_id, (Decimal("0"), "USD"))
        if self.capture_result == "wrong_amount":
            amt = amt + Decimal("1.00")   # simula que PayPal capturó por otro valor
        return GatewayResult(ok=True, status="aprobado", gateway_ref=order_id,
                             raw_status="COMPLETED", card_brand="visa", card_last4="1111",
                             extra={"capture_id": "FAKE-CAP-1", "payer_email": "p@x.com",
                                    "captured_amount": f"{amt:.2f}", "captured_currency": cur_})

    def refund(self, ref, amount=None):
        self.refunded.append(ref)
        return GatewayResult(ok=True, status="reembolsado", gateway_ref="FAKE-REF-1")


@pytest.fixture
def fake_gw(monkeypatch):
    gw = FakeOrdersGateway()
    monkeypatch.setattr(pago_app, "get_gateway", lambda name=None: gw)
    return gw


def _payment(db_conn, charge_id):
    with db_conn.cursor() as cur:
        cur.execute("SELECT status, gateway_ref, gateway_capture_ref, receipt_number "
                    "FROM pago_payments WHERE charge_id=%s ORDER BY created_at DESC LIMIT 1",
                    (charge_id,))
        return cur.fetchone()


def _charge_status(db_conn, charge_id):
    with db_conn.cursor() as cur:
        cur.execute("SELECT status FROM pago_charges WHERE id=%s", (charge_id,))
        return cur.fetchone()[0]


class TestPayPalFlow:
    def test_orden_y_captura_aprobada(self, client, seed, db_conn, fake_gw):
        s = seed["make_charge"]()
        r = client.post(f"/api/public/pay/{s['token']}/paypal/order", json={})
        assert r.status_code == 200
        order_id = r.get_json()["order_id"]
        assert order_id == "FAKE-ORD-1"

        r = client.post(f"/api/public/pay/{s['token']}/paypal/capture", json={"order_id": order_id})
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "aprobado" and d["receipt_number"].startswith("REC-")
        assert _charge_status(db_conn, s["charge_id"]) == "pagado"
        status, _ref, cap, receipt = _payment(db_conn, s["charge_id"])
        assert status == "aprobado" and cap == "FAKE-CAP-1" and receipt

    def test_captura_monto_distinto_se_rechaza_y_reembolsa(self, client, seed, db_conn, fake_gw):
        # Seguridad (R3): si PayPal captura por un monto != al del cobro, se anula y reembolsa.
        s = seed["make_charge"]()
        oid = client.post(f"/api/public/pay/{s['token']}/paypal/order", json={}).get_json()["order_id"]
        fake_gw.capture_result = "wrong_amount"
        r = client.post(f"/api/public/pay/{s['token']}/paypal/capture", json={"order_id": oid})
        assert r.status_code == 409
        assert _charge_status(db_conn, s["charge_id"]) != "pagado"
        status, *_ = _payment(db_conn, s["charge_id"])
        assert status == "rechazado"
        assert fake_gw.refunded   # se pidió el reembolso automático

    def test_captura_repetida_no_reprocesa(self, client, seed, fake_gw):
        s = seed["make_charge"]()
        oid = client.post(f"/api/public/pay/{s['token']}/paypal/order", json={}).get_json()["order_id"]
        client.post(f"/api/public/pay/{s['token']}/paypal/capture", json={"order_id": oid})
        r = client.post(f"/api/public/pay/{s['token']}/paypal/capture", json={"order_id": oid})
        assert r.status_code in (404, 409)

    def test_declined_con_retry_mantiene_orden_viva(self, client, seed, db_conn, fake_gw):
        s = seed["make_charge"]()
        oid = client.post(f"/api/public/pay/{s['token']}/paypal/order", json={}).get_json()["order_id"]
        fake_gw.capture_result = "retry"
        r = client.post(f"/api/public/pay/{s['token']}/paypal/capture", json={"order_id": oid})
        assert r.status_code == 200
        assert r.get_json()["retry"] is True
        status, *_ = _payment(db_conn, s["charge_id"])
        assert status == "iniciado"   # la misma orden puede reintentarse
        fake_gw.capture_result = "ok"
        r = client.post(f"/api/public/pay/{s['token']}/paypal/capture", json={"order_id": oid})
        assert r.get_json()["status"] == "aprobado"

    def test_orden_sobre_enlace_pagado_rechazada(self, client, seed, fake_gw):
        s = seed["make_charge"](status="pagado")
        r = client.post(f"/api/public/pay/{s['token']}/paypal/order", json={})
        assert r.status_code == 409

    def test_gateway_sin_ordenes_da_409(self, client, seed, monkeypatch):
        from gateways.sandbox import SandboxGateway
        monkeypatch.setattr(pago_app, "get_gateway", lambda name=None: SandboxGateway())
        s = seed["make_charge"]()
        r = client.post(f"/api/public/pay/{s['token']}/paypal/order", json={})
        assert r.status_code == 409

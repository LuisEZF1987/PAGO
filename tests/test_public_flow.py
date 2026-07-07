"""Flujo publico completo: pagina del enlace + pago con tarjeta (sandbox)."""
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.db


def _charge_status(db_conn, charge_id):
    with db_conn.cursor() as cur:
        cur.execute("SELECT status FROM pago_charges WHERE id=%s", (charge_id,))
        return cur.fetchone()[0]


class TestPayPage:
    def test_pagina_activa(self, client, seed):
        s = seed["make_charge"]()
        r = client.get(f"/pay/{s['token']}")
        assert r.status_code == 200
        assert "Equipo medico de prueba" in r.get_data(as_text=True)

    def test_token_invalido(self, client, seed):
        r = client.get("/pay/no-existe-este-token")
        assert r.status_code == 404

    def test_enlace_vencido(self, client, seed):
        s = seed["make_charge"](expires=datetime.now(timezone.utc) - timedelta(days=1))
        r = client.get(f"/pay/{s['token']}")
        assert r.status_code == 200
        assert "vencido" in r.get_data(as_text=True).lower()


class TestCardPayment:
    def test_aprobado(self, client, seed, db_conn):
        s = seed["make_charge"]()
        r = client.post(f"/api/public/pay/{s['token']}/card",
                        json={"card_token": "tok_ok", "payer_name": "Juan", "payer_email": "j@x.ec"})
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "aprobado"
        assert d["receipt_number"].startswith("REC-")
        assert _charge_status(db_conn, s["charge_id"]) == "pagado"

    def test_no_paga_dos_veces(self, client, seed):
        s = seed["make_charge"]()
        assert client.post(f"/api/public/pay/{s['token']}/card",
                           json={"card_token": "tok_ok"}).status_code == 200
        r = client.post(f"/api/public/pay/{s['token']}/card", json={"card_token": "tok_ok"})
        assert r.status_code == 409

    def test_rechazado_cobro_sigue_pendiente(self, client, seed, db_conn):
        s = seed["make_charge"]()
        r = client.post(f"/api/public/pay/{s['token']}/card", json={"card_token": "tok_rechazada"})
        assert r.status_code == 200
        assert r.get_json()["status"] == "rechazado"
        assert _charge_status(db_conn, s["charge_id"]) == "pendiente"

    def test_error_pasarela_502(self, client, seed, db_conn):
        s = seed["make_charge"]()
        r = client.post(f"/api/public/pay/{s['token']}/card", json={"card_token": "tok_error"})
        assert r.status_code == 502
        assert _charge_status(db_conn, s["charge_id"]) == "pendiente"

    def test_enlace_vencido_no_cobra(self, client, seed):
        s = seed["make_charge"](expires=datetime.now(timezone.utc) - timedelta(days=1))
        r = client.post(f"/api/public/pay/{s['token']}/card", json={"card_token": "tok_ok"})
        assert r.status_code == 409

    def test_metodo_no_permitido(self, client, seed):
        s = seed["make_charge"](methods=["transferencia"])
        r = client.post(f"/api/public/pay/{s['token']}/card", json={"card_token": "tok_ok"})
        assert r.status_code == 409

    def test_recibo_pdf_publico(self, client, seed):
        s = seed["make_charge"]()
        client.post(f"/api/public/pay/{s['token']}/card", json={"card_token": "tok_ok"})
        r = client.get(f"/pay/{s['token']}/recibo.pdf")
        assert r.status_code == 200
        assert r.data.startswith(b"%PDF")

    def test_recibo_no_disponible_si_pendiente(self, client, seed):
        s = seed["make_charge"]()
        assert client.get(f"/pay/{s['token']}/recibo.pdf").status_code == 404

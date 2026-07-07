"""Transferencias: upload del comprobante + conciliacion (aprobar/rechazar)."""
import io

import pytest

pytestmark = pytest.mark.db

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def _submit(client, token, content=PNG, filename="comprobante.png", reference="REF-001"):
    return client.post(f"/api/public/pay/{token}/transfer", data={
        "reference": reference, "bank_name": "Banco Test", "payer_name": "Juan",
        "file": (io.BytesIO(content), filename),
    }, content_type="multipart/form-data")


def _charge_status(db_conn, charge_id):
    with db_conn.cursor() as cur:
        cur.execute("SELECT status FROM pago_charges WHERE id=%s", (charge_id,))
        return cur.fetchone()[0]


def _payment_of(db_conn, charge_id):
    with db_conn.cursor() as cur:
        cur.execute("SELECT id, status FROM pago_payments WHERE charge_id=%s "
                    "ORDER BY created_at DESC LIMIT 1", (charge_id,))
        return cur.fetchone()


class TestUpload:
    def test_comprobante_valido(self, client, seed, db_conn):
        s = seed["make_charge"]()
        r = _submit(client, s["token"])
        assert r.status_code == 200
        assert r.get_json()["status"] == "en_revision"
        assert _charge_status(db_conn, s["charge_id"]) == "en_revision"

    def test_magic_bytes_falsos(self, client, seed):
        s = seed["make_charge"]()
        r = _submit(client, s["token"], content=b"no soy un png", filename="fake.png")
        assert r.status_code == 400

    def test_extension_prohibida(self, client, seed):
        s = seed["make_charge"]()
        r = _submit(client, s["token"], filename="script.exe")
        assert r.status_code == 400

    def test_sin_referencia(self, client, seed):
        s = seed["make_charge"]()
        r = _submit(client, s["token"], reference="")
        assert r.status_code == 400

    def test_comprobante_exige_auth_para_verlo(self, client, seed, db_conn):
        s = seed["make_charge"]()
        _submit(client, s["token"])
        with db_conn.cursor() as cur:
            cur.execute("SELECT tr.id FROM pago_transfer_receipts tr "
                        "JOIN pago_payments p ON p.id=tr.payment_id WHERE p.charge_id=%s",
                        (s["charge_id"],))
            rid = cur.fetchone()[0]
        assert client.get(f"/api/pago/comprobantes/{rid}").status_code == 401


class TestConciliacion:
    def _auth(self, client, seed, role="admin"):
        staff = seed["make_staff"](role)
        client.set_cookie("pago_token", staff["token"])
        return staff

    def test_aprobar(self, client, seed, db_conn):
        s = seed["make_charge"]()
        _submit(client, s["token"])
        pid, _ = _payment_of(db_conn, s["charge_id"])
        self._auth(client, seed)
        r = client.post(f"/api/pago/pagos/{pid}/aprobar")
        assert r.status_code == 200
        assert r.get_json()["receipt_number"].startswith("REC-")
        assert _charge_status(db_conn, s["charge_id"]) == "pagado"

    def test_rechazar_vuelve_a_pendiente(self, client, seed, db_conn):
        s = seed["make_charge"]()
        _submit(client, s["token"])
        pid, _ = _payment_of(db_conn, s["charge_id"])
        self._auth(client, seed)
        r = client.post(f"/api/pago/pagos/{pid}/rechazar", json={"motivo": "No llego el dinero"})
        assert r.status_code == 200
        assert _charge_status(db_conn, s["charge_id"]) == "pendiente"
        _, pstatus = _payment_of(db_conn, s["charge_id"])
        assert pstatus == "rechazado"

    def test_cobrador_no_aprueba(self, client, seed, db_conn):
        s = seed["make_charge"]()
        _submit(client, s["token"])
        pid, _ = _payment_of(db_conn, s["charge_id"])
        self._auth(client, seed, role="cobrador")
        assert client.post(f"/api/pago/pagos/{pid}/aprobar").status_code == 403

    def test_pago_manual_efectivo(self, client, seed, db_conn):
        s = seed["make_charge"]()
        self._auth(client, seed)
        r = client.post("/api/pago/pagos", json={"charge_id": str(s["charge_id"]), "method": "efectivo"})
        assert r.status_code == 201
        assert _charge_status(db_conn, s["charge_id"]) == "pagado"

    def test_reembolso_tarjeta(self, client, seed, db_conn):
        s = seed["make_charge"]()
        client.delete_cookie("pago_token")
        client.post(f"/api/public/pay/{s['token']}/card", json={"card_token": "tok_ok"})
        pid, _ = _payment_of(db_conn, s["charge_id"])
        self._auth(client, seed)
        r = client.post(f"/api/pago/pagos/{pid}/reembolsar", json={})
        assert r.status_code == 200
        assert _charge_status(db_conn, s["charge_id"]) == "reembolsado"

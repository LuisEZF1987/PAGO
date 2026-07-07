"""Configuracion comun de pytest para dimed-pago.

El codigo de la app vive en `pago/` (pago_app.py, gateways/, validators.py),
asi que lo agregamos al path y fijamos variables minimas para poder importarlo
sin un entorno real. Las pruebas que tocan la BD usan el fixture `db_conn`,
que se omite con gracia si no hay PostgreSQL disponible.
"""
import os
import secrets
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

PAGO_DIR = Path(__file__).resolve().parent.parent / "pago"
sys.path.insert(0, str(PAGO_DIR))

os.environ.setdefault("JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_PORT", "5432")
os.environ.setdefault("DB_NAME", "dimed_pago")
os.environ.setdefault("PG_USER", "dimed")
os.environ.setdefault("PG_PASSWORD", "")
os.environ.setdefault("GATEWAY", "sandbox")
os.environ.setdefault("UPLOAD_DIR", tempfile.mkdtemp(prefix="pago-uploads-"))


def _db_params():
    return dict(
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "5432")),
        dbname=os.environ.get("DB_NAME", "dimed_pago"),
        user=os.environ.get("PG_USER", "dimed"),
        password=os.environ.get("PG_PASSWORD", ""),
    )


@pytest.fixture
def db_conn():
    """Conexion a Postgres para los tests marcados @pytest.mark.db.

    Si no hay BD accesible, el test se omite (skip) en vez de fallar.
    """
    psycopg2 = pytest.importorskip("psycopg2")
    try:
        conn = psycopg2.connect(connect_timeout=3, **_db_params())
    except Exception as e:  # noqa: BLE001 - cualquier fallo de conexion -> skip
        pytest.skip(f"sin PostgreSQL disponible ({e.__class__.__name__})")
    try:
        yield conn
    finally:
        try:
            conn.rollback()
        finally:
            conn.close()


@pytest.fixture
def client():
    import pago_app
    pago_app.app.config["TESTING"] = True
    return pago_app.app.test_client()


@pytest.fixture
def seed(db_conn):
    """Crea cliente + cobros COMPROMETIDOS (visibles para la app) y limpia al final."""
    import pago_app

    created = {"customers": [], "charges": [], "users": []}

    def make_charge(amount="150.00", methods=None, expires=None, status="pendiente"):
        with db_conn.cursor() as cur:
            cur.execute("INSERT INTO pago_customers (name, doc_type) VALUES (%s,'pasaporte') RETURNING id",
                        (f"Cliente Test {uuid.uuid4().hex[:8]}",))
            cid = cur.fetchone()[0]
            token = pago_app.new_link_token()
            cur.execute(
                "INSERT INTO pago_charges (customer_id, concept, amount, status, link_token, "
                "link_expires_at, allowed_methods) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (cid, "Equipo medico de prueba", amount, status, token,
                 expires, list(methods or ["tarjeta", "transferencia"])))
            chid = cur.fetchone()[0]
        db_conn.commit()
        created["customers"].append(cid)
        created["charges"].append(chid)
        return {"customer_id": cid, "charge_id": chid, "token": token}

    def make_staff(role="admin"):
        bcrypt = pytest.importorskip("bcrypt")
        username = f"test_{uuid.uuid4().hex[:10]}"
        pw_hash = bcrypt.hashpw(b"x", bcrypt.gensalt(rounds=4)).decode()
        with db_conn.cursor() as cur:
            cur.execute("INSERT INTO pago_users (username,email,password_hash,full_name,role) "
                        "VALUES (%s,%s,%s,%s,%s) RETURNING id",
                        (username, f"{username}@test.local", pw_hash, "Staff Test", role))
            uid = cur.fetchone()[0]
        db_conn.commit()
        created["users"].append(uid)
        token = pago_app._create_token({"id": uid, "username": username,
                                        "email": None, "full_name": "Staff Test", "role": role})
        return {"id": uid, "token": token}

    yield {"make_charge": make_charge, "make_staff": make_staff}

    with db_conn.cursor() as cur:
        for chid in created["charges"]:
            cur.execute("DELETE FROM pago_transfer_receipts WHERE payment_id IN "
                        "(SELECT id FROM pago_payments WHERE charge_id=%s)", (chid,))
            cur.execute("DELETE FROM pago_gateway_events WHERE payment_id IN "
                        "(SELECT id FROM pago_payments WHERE charge_id=%s)", (chid,))
            cur.execute("DELETE FROM pago_payments WHERE charge_id=%s", (chid,))
            cur.execute("DELETE FROM pago_charges WHERE id=%s", (chid,))
        for cid in created["customers"]:
            cur.execute("DELETE FROM pago_customers WHERE id=%s", (cid,))
        for uid in created["users"]:
            cur.execute("UPDATE pago_audit_log SET user_id=NULL WHERE user_id=%s", (uid,))
            cur.execute("DELETE FROM pago_2fa_recovery WHERE user_id=%s", (uid,))
            cur.execute("DELETE FROM pago_users WHERE id=%s", (uid,))
    db_conn.commit()

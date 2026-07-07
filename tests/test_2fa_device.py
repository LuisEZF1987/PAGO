"""Re-mostrar QR (con contrasena) y verificar el dispositivo: el QR nunca se persiste."""
import pytest

pytestmark = pytest.mark.db


@pytest.fixture
def user_2fa(db_conn, seed):
    """Staff con 2FA ya activado; devuelve (staff, secret, password)."""
    import bcrypt
    import dimed_2fa
    import pago_app
    staff = seed["make_staff"]("admin")
    secret = dimed_2fa.generate_secret()
    password = "Clave.De.Prueba.123"
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode()
    with db_conn.cursor() as cur:
        cur.execute("UPDATE pago_users SET totp_enabled=TRUE, totp_secret=%s, password_hash=%s "
                    "WHERE id=%s",
                    (dimed_2fa.encrypt_secret(secret, pago_app.JWT_SECRET), pw_hash, staff["id"]))
    db_conn.commit()
    return staff, secret, password


def _auth(client, staff):
    client.set_cookie("pago_token", staff["token"])


class TestQr:
    def test_contrasena_incorrecta(self, client, user_2fa):
        staff, _secret, _pw = user_2fa
        _auth(client, staff)
        r = client.post("/api/auth/2fa/qr", json={"password": "mala"})
        assert r.status_code == 401

    def test_qr_con_contrasena(self, client, user_2fa):
        staff, secret, pw = user_2fa
        _auth(client, staff)
        r = client.post("/api/auth/2fa/qr", json={"password": pw})
        assert r.status_code == 200
        d = r.get_json()
        assert d["setup_key"] == secret
        assert len(d["qr_png_base64"]) > 100
        assert d["otpauth_uri"].startswith("otpauth://totp/")

    def test_sin_2fa_activado(self, client, seed):
        staff = seed["make_staff"]("admin")
        _auth(client, staff)
        r = client.post("/api/auth/2fa/qr", json={"password": "x"})
        assert r.status_code == 400


class TestVerify:
    def test_codigo_valido_y_antireplay(self, client, user_2fa):
        import pyotp
        staff, secret, _pw = user_2fa
        _auth(client, staff)
        code = pyotp.TOTP(secret).now()
        r = client.post("/api/auth/2fa/verify", json={"code": code})
        assert r.status_code == 200 and r.get_json()["ok"] is True
        # replay del mismo codigo: rechazado (contador ya consumido)
        r = client.post("/api/auth/2fa/verify", json={"code": code})
        assert r.status_code == 401

    def test_codigo_basura(self, client, user_2fa):
        staff, _secret, _pw = user_2fa
        _auth(client, staff)
        r = client.post("/api/auth/2fa/verify", json={"code": "000000"})
        assert r.status_code == 401

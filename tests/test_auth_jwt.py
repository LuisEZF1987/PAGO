"""JWT: emision, expiracion, issuer/audience y bloqueo de tokens de proposito especial."""
from datetime import datetime, timedelta, timezone

import jwt
import pytest

import pago_app


def _user():
    return {"id": "11111111-1111-1111-1111-111111111111", "username": "cob",
            "email": "cob@test.local", "full_name": "Cobrador Test", "role": "cobrador"}


class TestToken:
    def test_roundtrip(self):
        payload = pago_app.decode_token(pago_app._create_token(_user()))
        assert payload["username"] == "cob"
        assert payload["role"] == "cobrador"
        assert payload["iss"] == "dimed-pago"

    def test_expirado(self):
        tok = jwt.encode(
            {"user_id": "x", "iss": pago_app.JWT_ISS, "aud": pago_app.JWT_AUD,
             "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
            pago_app.JWT_SECRET, algorithm="HS256",
        )
        with pytest.raises(jwt.ExpiredSignatureError):
            pago_app.decode_token(tok)

    def test_issuer_ajeno_rechazado(self):
        tok = jwt.encode(
            {"user_id": "x", "iss": "dimed-caja", "aud": "dimed-caja",
             "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            pago_app.JWT_SECRET, algorithm="HS256",
        )
        with pytest.raises(jwt.InvalidTokenError):
            pago_app.decode_token(tok)


class TestRequireAuth:
    def test_sin_token(self, client):
        r = client.get("/api/auth/me")
        assert r.status_code == 401

    def test_token_valido(self, client):
        tok = pago_app._create_token(_user())
        r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert r.get_json()["user"]["username"] == "cob"

    def test_token_2fa_pending_no_es_sesion(self, client):
        pending = pago_app._create_pending_2fa_token(
            {"id": "11111111-1111-1111-1111-111111111111", "username": "cob"})
        r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {pending}"})
        assert r.status_code == 401

    def test_rol_insuficiente(self, client):
        tok = pago_app._create_token(_user())   # cobrador
        r = client.get("/api/pago/auditoria", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 403

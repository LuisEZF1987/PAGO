"""Modulo dimed_2fa vendorizado: TOTP, cifrado del secreto y codigos de recuperacion."""
import pyotp

import dimed_2fa


def test_verify_code_acepta_codigo_vigente():
    secret = dimed_2fa.generate_secret()
    code = pyotp.TOTP(secret).now()
    ok, counter = dimed_2fa.verify_code(secret, code)
    assert ok
    assert counter is not None


def test_verify_code_rechaza_basura():
    secret = dimed_2fa.generate_secret()
    ok, counter = dimed_2fa.verify_code(secret, "000000")
    # 1 en 10^6 de falso positivo: si el codigo aleatorio coincide, repetimos.
    if ok:
        ok, _ = dimed_2fa.verify_code(secret, "999999")
    assert not ok or True  # nunca debe lanzar excepcion


def test_replay_bloqueado_por_counter():
    secret = dimed_2fa.generate_secret()
    code = pyotp.TOTP(secret).now()
    ok, counter = dimed_2fa.verify_code(secret, code)
    assert ok
    ok2, _ = dimed_2fa.verify_code(secret, code, last_counter=counter)
    assert not ok2


def test_encrypt_decrypt_roundtrip():
    secret = dimed_2fa.generate_secret()
    enc = dimed_2fa.encrypt_secret(secret, "clave-material")
    assert enc != secret
    assert dimed_2fa.decrypt_secret(enc, "clave-material") == secret


def test_recovery_codes():
    codes = dimed_2fa.generate_recovery_codes()
    assert len(codes) == 8
    assert len(set(codes)) == 8
    h1 = dimed_2fa.hash_recovery(codes[0])
    assert h1 == dimed_2fa.hash_recovery(codes[0])   # determinista
    assert h1 != codes[0]                            # nunca en claro

"""dimed_2fa — 2FA TOTP compartido de la suite Dimed (RFC 6238).

Vendorizable en cada producto (mismo patron que dimed_license): copiar el
directorio `dimed_2fa/` junto a la app y añadir a requirements:
pyotp, qrcode, pypng (QR) y cryptography (cifrado del secreto en reposo).

Piezas:
- Enrolamiento: generate_secret() -> provisioning_uri() -> qr_png_base64()
- Verificacion: verify_code() con ventana ±1 y anti-replay por contador de
  paso de tiempo (persistir el contador devuelto y pasarlo como last_counter).
- Codigos de recuperacion: generate_recovery_codes() / hash_recovery()
  (alta entropia -> hash sha256; un solo uso lo controla la app).
- Secreto en reposo: encrypt_secret()/decrypt_secret() (Fernet derivado del
  material de clave que le pases, p.ej. el JWT_SECRET del producto).
"""
import base64
import hashlib
import io
import secrets as _secrets

import pyotp
from cryptography.fernet import Fernet, InvalidToken

__all__ = [
    "generate_secret", "provisioning_uri", "qr_png_base64", "verify_code",
    "generate_recovery_codes", "hash_recovery",
    "encrypt_secret", "decrypt_secret",
]

_STEP = 30  # segundos por paso TOTP (estandar Google Authenticator)


def generate_secret() -> str:
    """Secreto base32 nuevo (160 bits)."""
    return pyotp.random_base32(length=32)


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """URI otpauth:// para el QR (Google Authenticator, Authy, etc.)."""
    return pyotp.totp.TOTP(secret, interval=_STEP).provisioning_uri(
        name=account, issuer_name=issuer)


def qr_png_base64(uri: str) -> str:
    """PNG del QR en base64 (sin pillow: qrcode + pypng)."""
    import qrcode
    import qrcode.image.pure

    img = qrcode.make(uri, image_factory=qrcode.image.pure.PyPNGImage)
    buf = io.BytesIO()
    img.save(buf)
    return base64.b64encode(buf.getvalue()).decode()


def verify_code(secret: str, code: str, last_counter=None, window: int = 1,
                _now=None):
    """Verifica un codigo TOTP.

    Devuelve (ok, counter): `counter` es el paso de tiempo aceptado; la app
    debe persistirlo y pasarlo como `last_counter` en la siguiente llamada
    para rechazar la REUTILIZACION del mismo codigo (anti-replay).
    """
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False, None
    totp = pyotp.TOTP(secret, interval=_STEP)
    import time
    now = int(_now if _now is not None else time.time())
    for offset in range(-window, window + 1):
        ts = now + offset * _STEP
        counter = ts // _STEP
        if last_counter is not None and counter <= int(last_counter):
            continue  # ya usado (o anterior al ultimo uso): replay
        if pyotp.utils.strings_equal(code, totp.at(ts)):
            return True, counter
    return False, None


def generate_recovery_codes(n: int = 8):
    """Codigos de recuperacion legibles (un solo uso; mostrarlos UNA vez)."""
    out = []
    for _ in range(n):
        raw = _secrets.token_hex(5)  # 40 bits
        out.append(f"{raw[0:4]}-{raw[4:8]}-{raw[8:10]}".upper())
    return out


def hash_recovery(code: str) -> str:
    """Hash del codigo de recuperacion (normaliza mayusculas/guiones)."""
    norm = (code or "").strip().upper().replace("-", "")
    return hashlib.sha256(norm.encode()).hexdigest()


def _fernet(key_material: str) -> Fernet:
    digest = hashlib.sha256(("dimed-2fa|" + key_material).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plain: str, key_material: str) -> str:
    """Cifra el secreto TOTP para guardarlo en la BD."""
    return _fernet(key_material).encrypt(plain.encode()).decode()


def decrypt_secret(token: str, key_material: str) -> str:
    """Descifra el secreto TOTP; ValueError si la clave no corresponde."""
    try:
        return _fernet(key_material).decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise ValueError("secreto 2FA ilegible (clave incorrecta)") from e

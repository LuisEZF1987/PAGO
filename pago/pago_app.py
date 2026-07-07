"""
Dimed-PAGO — cobros con enlace de pago (tarjeta via pasarela pluggable,
transferencia con comprobante, efectivo/cheque) para la empresa.

PCI-DSS: este servidor JAMAS recibe ni almacena PAN/CVV. La tarjeta se
tokeniza en el navegador (SDK del gateway); aqui solo llegan tokens opacos y
se persisten gateway_ref / card_brand / card_last4.
"""
import functools
import io
import logging
import os
import secrets
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

import bcrypt
import jwt
import psycopg2
import psycopg2.errors
import psycopg2.extras
import psycopg2.pool
from flask import Flask, g, jsonify, redirect, render_template, request, send_file
from werkzeug.middleware.proxy_fix import ProxyFix

import dimed_2fa
from gateways import GatewayError, get_gateway, known_gateway
from log_redaction import install_phi_redaction
from validators import validar_documento, validar_password

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("dimed-pago")
install_phi_redaction()

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "dimed_pago")
DB_USER = os.environ.get("PG_USER", "dimed")
DB_PASS = os.environ.get("PG_PASSWORD", "")

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "4"))
JWT_ISS = JWT_AUD = "dimed-pago"   # issuer/audience: ata el token a este sistema (anti-replay)
COOKIE_NAME = "pago_token"

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://localhost:9850").rstrip("/")
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "10"))
UPLOAD_DIR = os.path.abspath(os.environ.get("UPLOAD_DIR", "/app/uploads"))

STAFF = ["super_admin", "admin", "cobrador"]
ADMINS = ["super_admin", "admin"]

app = Flask(__name__, template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# ---------------------------------------------------------------------------
# Pool DB
# ---------------------------------------------------------------------------
_pool = None


def _get_pool():
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2, maxconn=10, host=DB_HOST, port=DB_PORT,
            dbname=DB_NAME, user=DB_USER, password=DB_PASS,
        )
    return _pool


def get_db():
    return _get_pool().getconn()


def put_db(conn):
    try:
        _get_pool().putconn(conn)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _dec(row):
    if not row:
        return row
    out = dict(row)
    for k, v in out.items():
        if isinstance(v, Decimal):
            out[k] = float(v)
        elif hasattr(v, "isoformat"):
            out[k] = v.isoformat()
        elif isinstance(v, uuid.UUID):
            out[k] = str(v)
    return out


def get_config(cur):
    cur.execute("SELECT key, value FROM pago_config")
    return {k: v for k, v in cur.fetchall()}


def _parse_amount(raw):
    """Monto en USD con 2 decimales, > 0. Devuelve Decimal o None."""
    try:
        amt = Decimal(str(raw)).quantize(Decimal("0.01"))
    except (InvalidOperation, TypeError, ValueError):
        return None
    return amt if amt > 0 else None


# ---------------------------------------------------------------------------
# JWT / sesion
# ---------------------------------------------------------------------------
def decode_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"],
                      audience=JWT_AUD, issuer=JWT_ISS)


def _create_token(user):
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": str(user["id"]),
        "username": user["username"],
        "email": user.get("email"),
        "full_name": user.get("full_name"),
        "role": user["role"],
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=JWT_EXPIRY_HOURS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _reissue_token(payload):
    """Re-emite un token con los mismos datos de identidad y vigencia renovada."""
    return _create_token({
        "id": payload["user_id"], "username": payload["username"],
        "email": payload.get("email"), "full_name": payload.get("full_name"),
        "role": payload["role"],
    })


def _mark_sliding_refresh(payload):
    """Refresh deslizante: si el token paso la mitad de su vida, marca para
    re-emitir la cookie en la respuesta (transparente para el usuario activo)."""
    try:
        now = int(datetime.now(timezone.utc).timestamp())
        iat, exp = payload.get("iat"), payload.get("exp")
        if iat and exp and now > iat + (exp - iat) // 2:
            g.sliding_token = _reissue_token(payload)
    except Exception:
        pass


def _set_session_cookie(resp, token):
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="Strict", path="/",
                    max_age=JWT_EXPIRY_HOURS * 3600,
                    secure=os.getenv("FLASK_ENV") == "production")


@app.after_request
def _harden_and_refresh(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    tok = getattr(g, "sliding_token", None)
    if tok:
        _set_session_cookie(response, tok)
    return response


def log_audit(user_id, action, entity=None, entity_id=None, details=None, ip=None):
    """Registro de auditoria (best-effort). Conexion propia."""
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute("INSERT INTO pago_audit_log (user_id,action,entity,entity_id,details,ip_address) "
                      "VALUES (%s,%s,%s,%s,%s,%s)",
                      (user_id, action, entity, str(entity_id) if entity_id is not None else None,
                       psycopg2.extras.Json(details) if details else None, ip))
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        put_db(conn)


def _record_login_attempt(username, ip, success):
    conn = get_db()
    try:
        with conn.cursor() as c:
            c.execute("INSERT INTO pago_login_attempts (username, ip_address, success) VALUES (%s,%s,%s)",
                      (username, ip, success))
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        put_db(conn)


def _token_from_request():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return request.cookies.get(COOKIE_NAME)


def require_auth(allowed_roles=None):
    """Auth por JWT (cookie o Bearer) con restriccion opcional de rol."""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            token = _token_from_request()
            if not token:
                return jsonify({"error": "Token no proporcionado"}), 401
            try:
                payload = decode_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expirado"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Token invalido"}), 401
            if payload.get("purpose"):
                # Tokens de proposito especial (p.ej. 2fa-pending) NO son sesion:
                # sin esto, el primer factor bastaria para llamar a la API.
                return jsonify({"error": "Token invalido"}), 401
            if allowed_roles and payload.get("role") not in allowed_roles:
                return jsonify({"error": "No tiene permisos para esta accion"}), 403
            _mark_sliding_refresh(payload)
            request.current_user = payload
            return f(*args, **kwargs)
        return wrapper
    return decorator


def _client_ip():
    # Con ProxyFix, remote_addr ya es la IP real del cliente (1 hop de confianza).
    return request.remote_addr or ""


# ---------------------------------------------------------------------------
# Rate limit (ventana fija en memoria; aproximado con varios workers, y los
# limites de negocio criticos se cuentan ademas en BD)
# ---------------------------------------------------------------------------
_rl_lock = threading.Lock()
_rl_buckets = {}


def rate_limit(max_requests, window_seconds):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            window = int(time.time()) // window_seconds
            key = (f.__name__, _client_ip(), window)
            with _rl_lock:
                if len(_rl_buckets) > 10000:
                    _rl_buckets.clear()
                _rl_buckets[key] = _rl_buckets.get(key, 0) + 1
                count = _rl_buckets[key]
            if count > max_requests:
                return jsonify({"error": "Demasiadas solicitudes. Intente mas tarde."}), 429
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Maquina de estados (cobros y pagos)
# ---------------------------------------------------------------------------
CHARGE_TRANSITIONS = {
    "pendiente": {"pagado", "en_revision", "anulado"},
    "en_revision": {"pagado", "pendiente", "anulado"},
    "pagado": {"reembolsado"},
    "reembolsado": set(),
    "anulado": set(),
}
PAYMENT_TRANSITIONS = {
    "iniciado": {"aprobado", "rechazado"},
    "en_revision": {"aprobado", "rechazado"},
    "aprobado": {"reembolsado", "anulado"},
    "rechazado": set(),
    "reembolsado": set(),
    "anulado": set(),
}


def can_transition(kind, from_status, to_status):
    table = CHARGE_TRANSITIONS if kind == "charge" else PAYMENT_TRANSITIONS
    return to_status in table.get(from_status, set())


def _set_charge_status(cur, charge_id, from_status, to_status):
    """Transicion validada de un cobro DENTRO de la transaccion del caller."""
    if not can_transition("charge", from_status, to_status):
        raise ValueError(f"Transicion de cobro invalida: {from_status} -> {to_status}")
    cur.execute("UPDATE pago_charges SET status=%s, updated_at=NOW() WHERE id=%s AND status=%s",
                (to_status, charge_id, from_status))
    if cur.rowcount != 1:
        raise ValueError("El cobro cambio de estado; recargue e intente de nuevo")


def _next_receipt(cur):
    """Numero de recibo secuencial. Soporta cursor de tuplas y RealDictCursor."""
    cur.execute("SELECT 'REC-' || to_char(nextval('pago_receipt_seq'), 'FM000000') AS receipt")
    row = cur.fetchone()
    return row["receipt"] if isinstance(row, dict) else row[0]


# ---------------------------------------------------------------------------
# Enlaces de pago
# ---------------------------------------------------------------------------
def new_link_token():
    return secrets.token_urlsafe(32)   # 256 bits, no enumerable


def link_url(token):
    return f"{PUBLIC_BASE_URL}/pay/{token}"


def link_state(status, link_expires_at, now=None):
    """Estado efectivo de un enlace publico (funcion pura, testeable)."""
    if status == "anulado":
        return "anulado"
    if status in ("pagado", "reembolsado"):
        return "pagado"
    if status == "en_revision":
        return "en_revision"
    now = now or datetime.now(timezone.utc)
    if link_expires_at and link_expires_at < now:
        return "vencido"
    return "activo"


def _default_link_expiry(cur):
    try:
        days = int(get_config(cur).get("link_default_days", "90"))
    except ValueError:
        days = 90
    return datetime.now(timezone.utc) + timedelta(days=days) if days > 0 else None


def _load_charge_by_token(cur, token):
    cur.execute(
        "SELECT ch.*, cu.name AS customer_name, cu.email AS customer_email "
        "FROM pago_charges ch JOIN pago_customers cu ON cu.id = ch.customer_id "
        "WHERE ch.link_token = %s", (token,))
    return cur.fetchone()


# ---------------------------------------------------------------------------
# Validacion de comprobantes subidos (publico)
# ---------------------------------------------------------------------------
_UPLOAD_TYPES = {
    "pdf": (b"%PDF", "application/pdf"),
    "png": (b"\x89PNG", "image/png"),
    "jpg": (b"\xff\xd8", "image/jpeg"),
    "jpeg": (b"\xff\xd8", "image/jpeg"),
}


def validate_upload(filename, head):
    """(ok, ext_o_error, mime). Extension permitida Y magic bytes coherentes."""
    ext = (filename or "").rsplit(".", 1)[-1].lower() if "." in (filename or "") else ""
    if ext not in _UPLOAD_TYPES:
        return False, "Formato no permitido (use JPG, PNG o PDF)", None
    magic, mime = _UPLOAD_TYPES[ext]
    if not head.startswith(magic):
        return False, "El archivo no corresponde al formato declarado", None
    return True, ext, mime


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.route("/api/auth/login", methods=["POST"])
@rate_limit(10, 60)
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Usuario y contrasena requeridos"}), 400
    ip = _client_ip()
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pago_login_attempts WHERE username=%s AND success=FALSE "
                        "AND created_at > NOW() - INTERVAL '15 minutes'", (username,))
            fails_user = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM pago_login_attempts WHERE ip_address=%s AND success=FALSE "
                        "AND created_at > NOW() - INTERVAL '15 minutes'", (ip,))
            fails_ip = cur.fetchone()[0]
        if fails_user >= 5 or fails_ip >= 20:
            log_audit(None, "LOGIN_LOCKED", "Auth", None, {"username": username}, ip)
            return jsonify({"error": "Demasiados intentos fallidos. Espere unos minutos."}), 429

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id,username,email,password_hash,full_name,role,is_active,"
                        "totp_enabled FROM pago_users WHERE (username=%s OR email=%s) AND is_active=TRUE",
                        (username, username))
            user = cur.fetchone()
        if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            _record_login_attempt(username, ip, False)
            log_audit(None, "LOGIN_FAILED", "Auth", None, {"username": username}, ip)
            return jsonify({"error": "Credenciales invalidas"}), 401
        if user.get("totp_enabled"):
            log_audit(user["id"], "LOGIN_2FA_REQUIRED", "Auth", None, None, ip)
            return jsonify({"requires_2fa": True,
                            "pending_token": _create_pending_2fa_token(user)}), 200
        _record_login_attempt(username, ip, True)
        with conn.cursor() as cur:
            cur.execute("UPDATE pago_users SET last_login=NOW() WHERE id=%s", (user["id"],))
        conn.commit()
        token = _create_token(user)
        log_audit(user["id"], "LOGIN", "Auth", None, None, ip)
        resp = jsonify({"user": {"id": str(user["id"]), "username": user["username"],
                                 "full_name": user["full_name"], "role": user["role"]},
                        "redirect": "/"})
        _set_session_cookie(resp, token)
        return resp, 200
    except Exception:
        conn.rollback()
        log.exception("Error en login")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    resp = jsonify({"message": "Sesion cerrada"})
    resp.set_cookie(COOKIE_NAME, "", expires=0, httponly=True, samesite="Strict", path="/")
    return resp, 200


@app.route("/api/auth/me")
@require_auth()
def api_me():
    cu = request.current_user
    return jsonify({"user": {"username": cu.get("username"), "full_name": cu.get("full_name"),
                             "role": cu.get("role")}}), 200


@app.route("/api/auth/refresh", methods=["POST"])
def api_refresh():
    """Renueva la cookie de sesion si el token actual sigue siendo valido."""
    token = _token_from_request()
    if not token:
        return jsonify({"error": "No autenticado"}), 401
    try:
        payload = decode_token(token)
    except jwt.InvalidTokenError:
        return jsonify({"error": "No autenticado"}), 401
    if payload.get("purpose"):
        return jsonify({"error": "No autenticado"}), 401
    resp = jsonify({"ok": True})
    _set_session_cookie(resp, _reissue_token(payload))
    return resp, 200


# ---------------------------------------------------------------------------
# 2FA TOTP (modulo compartido dimed_2fa)
# ---------------------------------------------------------------------------
def _create_pending_2fa_token(user):
    """Token corto (5 min) que SOLO sirve para completar el segundo factor."""
    now = datetime.now(timezone.utc)
    return jwt.encode({"user_id": str(user["id"]), "username": user["username"],
                       "purpose": "2fa-pending", "iss": JWT_ISS, "aud": JWT_AUD,
                       "iat": int(now.timestamp()),
                       "exp": int((now + timedelta(minutes=5)).timestamp())},
                      JWT_SECRET, algorithm="HS256")


def _try_recovery_code(conn, user_id, code):
    """Consume un codigo de recuperacion sin usar. True si era valido."""
    h = dimed_2fa.hash_recovery(code)
    with conn.cursor() as cur:
        cur.execute("UPDATE pago_2fa_recovery SET used_at=NOW() "
                    "WHERE user_id=%s AND code_hash=%s AND used_at IS NULL RETURNING id",
                    (user_id, h))
        return cur.fetchone() is not None


@app.route("/api/auth/login/2fa", methods=["POST"])
@rate_limit(10, 60)
def api_login_2fa():
    """Segundo paso del login: valida el codigo TOTP (o de recuperacion)."""
    data = request.get_json(silent=True) or {}
    pending, code = data.get("pending_token", ""), data.get("code", "")
    ip = _client_ip()
    try:
        claims = decode_token(pending)
    except jwt.InvalidTokenError:
        return jsonify({"error": "Sesion de verificacion expirada. Ingrese de nuevo."}), 401
    if claims.get("purpose") != "2fa-pending":
        return jsonify({"error": "Token invalido"}), 401
    username = claims.get("username", "")
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pago_login_attempts WHERE username=%s AND success=FALSE "
                        "AND created_at > NOW() - INTERVAL '15 minutes'", (username,))
            if cur.fetchone()[0] >= 5:
                log_audit(None, "LOGIN_LOCKED", "Auth", None, {"username": username, "2fa": True}, ip)
                return jsonify({"error": "Demasiados intentos fallidos. Espere unos minutos."}), 429
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id,username,email,full_name,role,totp_secret,"
                        "totp_last_counter,totp_enabled FROM pago_users "
                        "WHERE id=%s AND is_active=TRUE", (claims["user_id"],))
            user = cur.fetchone()
        if not user or not user["totp_enabled"] or not user["totp_secret"]:
            return jsonify({"error": "2FA no configurado"}), 400

        ok = False
        try:
            secret = dimed_2fa.decrypt_secret(user["totp_secret"], JWT_SECRET)
            ok, counter = dimed_2fa.verify_code(secret, code, user["totp_last_counter"])
        except ValueError:
            log.error("Secreto 2FA ilegible para el usuario %s", user["username"])
            return jsonify({"error": "Error interno"}), 500
        if ok:
            with conn.cursor() as cur:
                cur.execute("UPDATE pago_users SET totp_last_counter=%s, last_login=NOW() "
                            "WHERE id=%s", (counter, user["id"]))
        elif _try_recovery_code(conn, user["id"], code):
            ok = True
            with conn.cursor() as cur:
                cur.execute("UPDATE pago_users SET last_login=NOW() WHERE id=%s", (user["id"],))
            log_audit(user["id"], "2FA_RECOVERY_USED", "Auth", None, None, ip)
        if not ok:
            conn.commit()
            _record_login_attempt(username, ip, False)
            log_audit(user["id"], "LOGIN_2FA_FAILED", "Auth", None, None, ip)
            return jsonify({"error": "Codigo incorrecto"}), 401
        conn.commit()
        _record_login_attempt(username, ip, True)
        token = _create_token(user)
        log_audit(user["id"], "LOGIN", "Auth", None, {"2fa": True}, ip)
        resp = jsonify({"user": {"id": str(user["id"]), "username": user["username"],
                                 "full_name": user["full_name"], "role": user["role"]},
                        "redirect": "/"})
        _set_session_cookie(resp, token)
        return resp, 200
    except Exception:
        conn.rollback()
        log.exception("Error en login 2FA")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/auth/2fa", methods=["GET"])
@require_auth()
def api_2fa_status():
    cu = request.current_user
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT totp_enabled FROM pago_users WHERE id=%s", (cu["user_id"],))
            row = cur.fetchone()
        return jsonify({"enabled": bool(row and row[0])}), 200
    finally:
        put_db(conn)


@app.route("/api/auth/2fa/enroll", methods=["POST"])
@require_auth()
def api_2fa_enroll():
    """Genera el secreto (pendiente) y devuelve QR para la app autenticadora."""
    cu = request.current_user
    ip = _client_ip()
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT totp_enabled FROM pago_users WHERE id=%s", (cu["user_id"],))
            row = cur.fetchone()
        if row and row[0]:
            return jsonify({"error": "2FA ya esta activado. Desactivelo primero."}), 400
        secret = dimed_2fa.generate_secret()
        uri = dimed_2fa.provisioning_uri(secret, cu.get("username") or "usuario", "Dimed Pago")
        with conn.cursor() as cur:
            cur.execute("UPDATE pago_users SET totp_pending_secret=%s WHERE id=%s",
                        (dimed_2fa.encrypt_secret(secret, JWT_SECRET), cu["user_id"]))
        conn.commit()
        log_audit(cu["user_id"], "2FA_ENROLL_START", "Auth", None, None, ip)
        return jsonify({"otpauth_uri": uri, "qr_png_base64": dimed_2fa.qr_png_base64(uri)}), 200
    except Exception:
        conn.rollback()
        log.exception("Error en enroll 2FA")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/auth/2fa/confirm", methods=["POST"])
@require_auth()
def api_2fa_confirm():
    """Confirma el enrolamiento con un codigo valido; entrega codigos de recuperacion."""
    cu = request.current_user
    code = (request.get_json(silent=True) or {}).get("code", "")
    ip = _client_ip()
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT totp_pending_secret FROM pago_users WHERE id=%s", (cu["user_id"],))
            row = cur.fetchone()
        if not row or not row[0]:
            return jsonify({"error": "No hay enrolamiento pendiente"}), 400
        try:
            secret = dimed_2fa.decrypt_secret(row[0], JWT_SECRET)
        except ValueError:
            return jsonify({"error": "Enrolamiento corrupto; genere el QR de nuevo"}), 400
        ok, counter = dimed_2fa.verify_code(secret, code)
        if not ok:
            return jsonify({"error": "Codigo incorrecto"}), 401
        recovery = dimed_2fa.generate_recovery_codes()
        with conn.cursor() as cur:
            cur.execute("UPDATE pago_users SET totp_secret=totp_pending_secret, "
                        "totp_pending_secret=NULL, totp_enabled=TRUE, totp_last_counter=%s "
                        "WHERE id=%s", (counter, cu["user_id"]))
            cur.execute("DELETE FROM pago_2fa_recovery WHERE user_id=%s", (cu["user_id"],))
            for c in recovery:
                cur.execute("INSERT INTO pago_2fa_recovery (user_id, code_hash) VALUES (%s,%s)",
                            (cu["user_id"], dimed_2fa.hash_recovery(c)))
        conn.commit()
        log_audit(cu["user_id"], "2FA_ENABLED", "Auth", None, None, ip)
        return jsonify({"enabled": True, "recovery_codes": recovery}), 200
    except Exception:
        conn.rollback()
        log.exception("Error en confirm 2FA")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/auth/2fa/disable", methods=["POST"])
@require_auth()
def api_2fa_disable():
    """Desactiva 2FA. Exige contrasena + un codigo vigente (TOTP o recuperacion)."""
    cu = request.current_user
    data = request.get_json(silent=True) or {}
    password, code = data.get("password", ""), data.get("code", "")
    ip = _client_ip()
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT password_hash,totp_secret,totp_last_counter,totp_enabled "
                        "FROM pago_users WHERE id=%s", (cu["user_id"],))
            row = cur.fetchone()
        if not row or not row["totp_enabled"]:
            return jsonify({"error": "2FA no esta activado"}), 400
        if not password or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
            return jsonify({"error": "Contrasena incorrecta"}), 401
        ok = False
        try:
            secret = dimed_2fa.decrypt_secret(row["totp_secret"], JWT_SECRET)
            ok, _counter = dimed_2fa.verify_code(secret, code, row["totp_last_counter"])
        except ValueError:
            ok = False
        if not ok and not _try_recovery_code(conn, cu["user_id"], code):
            conn.commit()
            return jsonify({"error": "Codigo incorrecto"}), 401
        with conn.cursor() as cur:
            cur.execute("UPDATE pago_users SET totp_secret=NULL, totp_pending_secret=NULL, "
                        "totp_enabled=FALSE, totp_last_counter=NULL WHERE id=%s", (cu["user_id"],))
            cur.execute("DELETE FROM pago_2fa_recovery WHERE user_id=%s", (cu["user_id"],))
        conn.commit()
        log_audit(cu["user_id"], "2FA_DISABLED", "Auth", None, None, ip)
        return jsonify({"enabled": False}), 200
    except Exception:
        conn.rollback()
        log.exception("Error en disable 2FA")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/auth/2fa/qr", methods=["POST"])
@rate_limit(10, 60)
@require_auth()
def api_2fa_qr():
    """Re-muestra el QR del 2FA ya activado (enrolar el telefono / cambio de
    dispositivo). Exige la contrasena; el QR se genera al vuelo y no se persiste."""
    cu = request.current_user
    password = (request.get_json(silent=True) or {}).get("password", "")
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT username,password_hash,totp_secret,totp_enabled "
                        "FROM pago_users WHERE id=%s", (cu["user_id"],))
            row = cur.fetchone()
        if not row or not row["totp_enabled"] or not row["totp_secret"]:
            return jsonify({"error": "2FA no esta activado"}), 400
        if not password or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
            log_audit(cu["user_id"], "2FA_QR_DENIED", "Auth", None, None, _client_ip())
            return jsonify({"error": "Contrasena incorrecta"}), 401
        try:
            secret = dimed_2fa.decrypt_secret(row["totp_secret"], JWT_SECRET)
        except ValueError:
            return jsonify({"error": "Secreto ilegible; desactive y reactive el 2FA"}), 500
        uri = dimed_2fa.provisioning_uri(secret, row["username"], "Dimed Pago")
        log_audit(cu["user_id"], "2FA_QR_VIEWED", "Auth", None, None, _client_ip())
        return jsonify({"otpauth_uri": uri, "qr_png_base64": dimed_2fa.qr_png_base64(uri),
                        "setup_key": secret}), 200
    finally:
        put_db(conn)


@app.route("/api/auth/2fa/verify", methods=["POST"])
@rate_limit(10, 60)
@require_auth()
def api_2fa_verify():
    """Confirma que el autenticador quedo bien registrado (el QR se oculta al pasar)."""
    cu = request.current_user
    code = (request.get_json(silent=True) or {}).get("code", "")
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT totp_secret,totp_last_counter,totp_enabled "
                        "FROM pago_users WHERE id=%s", (cu["user_id"],))
            row = cur.fetchone()
        if not row or not row["totp_enabled"] or not row["totp_secret"]:
            return jsonify({"error": "2FA no esta activado"}), 400
        try:
            secret = dimed_2fa.decrypt_secret(row["totp_secret"], JWT_SECRET)
        except ValueError:
            return jsonify({"error": "Error interno"}), 500
        ok, counter = dimed_2fa.verify_code(secret, code, row["totp_last_counter"])
        if not ok:
            return jsonify({"error": "Codigo incorrecto"}), 401
        with conn.cursor() as cur:
            cur.execute("UPDATE pago_users SET totp_last_counter=%s WHERE id=%s",
                        (counter, cu["user_id"]))
        conn.commit()
        log_audit(cu["user_id"], "2FA_DEVICE_VERIFIED", "Auth", None, None, _client_ip())
        return jsonify({"ok": True}), 200
    except Exception:
        conn.rollback()
        log.exception("Error verificando dispositivo 2FA")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


# ---------------------------------------------------------------------------
# Usuarios (staff)
# ---------------------------------------------------------------------------
@app.route("/api/pago/usuarios", methods=["GET"])
@require_auth(ADMINS)
def api_users_list():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id,username,email,full_name,role,is_active,totp_enabled,"
                        "last_login,created_at FROM pago_users ORDER BY created_at")
            rows = [_dec(r) for r in cur.fetchall()]
        return jsonify({"users": rows}), 200
    finally:
        put_db(conn)


@app.route("/api/pago/usuarios", methods=["POST"])
@require_auth(ADMINS)
def api_users_create():
    cu = request.current_user
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    full_name = (data.get("full_name") or "").strip()
    role = (data.get("role") or "cobrador").strip()
    password = data.get("password") or ""
    if not username or not email or not full_name:
        return jsonify({"error": "username, email y full_name son requeridos"}), 400
    if role not in ("admin", "cobrador"):
        return jsonify({"error": "Rol invalido"}), 400
    if role == "admin" and cu["role"] != "super_admin":
        return jsonify({"error": "Solo el super administrador crea administradores"}), 403
    ok, msg = validar_password(password)
    if not ok:
        return jsonify({"error": msg}), 400
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO pago_users (username,email,password_hash,full_name,role) "
                        "VALUES (%s,%s,%s,%s,%s) RETURNING id",
                        (username, email, pw_hash, full_name, role))
            uid = cur.fetchone()[0]
        conn.commit()
        log_audit(cu["user_id"], "USER_CREATED", "User", uid, {"username": username, "role": role},
                  _client_ip())
        return jsonify({"id": str(uid)}), 201
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Usuario o email ya existe"}), 409
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify({"error": getattr(e.diag, "message_primary", "Error de base de datos")}), 400
    finally:
        put_db(conn)


@app.route("/api/pago/usuarios/<uid>", methods=["PUT"])
@require_auth(ADMINS)
def api_users_update(uid):
    cu = request.current_user
    data = request.get_json(silent=True) or {}
    sets, vals = [], []
    for field in ("email", "full_name"):
        if data.get(field):
            sets.append(f"{field}=%s")
            vals.append(data[field].strip())
    if data.get("role"):
        if data["role"] not in ("admin", "cobrador"):
            return jsonify({"error": "Rol invalido"}), 400
        if cu["role"] != "super_admin":
            return jsonify({"error": "Solo el super administrador cambia roles"}), 403
        sets.append("role=%s")
        vals.append(data["role"])
    if "is_active" in data:
        sets.append("is_active=%s")
        vals.append(bool(data["is_active"]))
    if data.get("password"):
        ok, msg = validar_password(data["password"])
        if not ok:
            return jsonify({"error": msg}), 400
        sets.append("password_hash=%s")
        vals.append(bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode())
    if not sets:
        return jsonify({"error": "Nada que actualizar"}), 400
    vals.append(uid)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE pago_users SET " + ", ".join(sets) + " WHERE id=%s", vals)
            if cur.rowcount != 1:
                conn.rollback()
                return jsonify({"error": "Usuario no encontrado"}), 404
        conn.commit()
        log_audit(cu["user_id"], "USER_UPDATED", "User", uid,
                  {k: v for k, v in data.items() if k != "password"}, _client_ip())
        return jsonify({"ok": True}), 200
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Email ya existe"}), 409
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify({"error": getattr(e.diag, "message_primary", "Error de base de datos")}), 400
    finally:
        put_db(conn)


# ---------------------------------------------------------------------------
# Configuracion de empresa + cuentas bancarias
# ---------------------------------------------------------------------------
_CONFIG_KEYS = {"company_name", "company_ruc", "company_address", "company_phone",
                "company_email", "link_default_days"}


@app.route("/api/pago/config", methods=["GET"])
@require_auth(STAFF)
def api_config_get():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            return jsonify({"config": get_config(cur)}), 200
    finally:
        put_db(conn)


@app.route("/api/pago/config", methods=["PUT"])
@require_auth(ADMINS)
def api_config_put():
    data = request.get_json(silent=True) or {}
    updates = {k: str(v) for k, v in data.items() if k in _CONFIG_KEYS}
    if not updates:
        return jsonify({"error": "Nada que actualizar"}), 400
    conn = get_db()
    try:
        with conn.cursor() as cur:
            for k, v in updates.items():
                cur.execute("INSERT INTO pago_config (key,value) VALUES (%s,%s) "
                            "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()",
                            (k, v))
        conn.commit()
        log_audit(request.current_user["user_id"], "CONFIG_UPDATED", "Config", None, updates, _client_ip())
        return jsonify({"ok": True}), 200
    except Exception:
        conn.rollback()
        log.exception("Error actualizando config")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/pago/cuentas-bancarias", methods=["GET"])
@require_auth(STAFF)
def api_banks_list():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM pago_bank_accounts ORDER BY display_order, created_at")
            return jsonify({"accounts": [_dec(r) for r in cur.fetchall()]}), 200
    finally:
        put_db(conn)


@app.route("/api/pago/cuentas-bancarias", methods=["POST"])
@require_auth(ADMINS)
def api_banks_create():
    data = request.get_json(silent=True) or {}
    required = ("bank_name", "account_number", "holder_name")
    if not all((data.get(k) or "").strip() for k in required):
        return jsonify({"error": "bank_name, account_number y holder_name son requeridos"}), 400
    acc_type = data.get("account_type", "corriente")
    if acc_type not in ("corriente", "ahorros"):
        return jsonify({"error": "Tipo de cuenta invalido"}), 400
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO pago_bank_accounts (bank_name,account_type,account_number,holder_name,"
                "holder_doc,swift_bic,extra_instructions,display_order) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (data["bank_name"].strip(), acc_type, data["account_number"].strip(),
                 data["holder_name"].strip(), data.get("holder_doc"), data.get("swift_bic"),
                 data.get("extra_instructions"), int(data.get("display_order") or 0)))
            bid = cur.fetchone()[0]
        conn.commit()
        log_audit(request.current_user["user_id"], "BANK_ACCOUNT_CREATED", "BankAccount", bid,
                  {"bank": data["bank_name"]}, _client_ip())
        return jsonify({"id": str(bid)}), 201
    except Exception:
        conn.rollback()
        log.exception("Error creando cuenta bancaria")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/pago/cuentas-bancarias/<bid>", methods=["PUT"])
@require_auth(ADMINS)
def api_banks_update(bid):
    data = request.get_json(silent=True) or {}
    sets, vals = [], []
    for field in ("bank_name", "account_type", "account_number", "holder_name",
                  "holder_doc", "swift_bic", "extra_instructions"):
        if field in data:
            sets.append(f"{field}=%s")
            vals.append(data[field])
    if "display_order" in data:
        sets.append("display_order=%s")
        vals.append(int(data["display_order"] or 0))
    if "is_active" in data:
        sets.append("is_active=%s")
        vals.append(bool(data["is_active"]))
    if not sets:
        return jsonify({"error": "Nada que actualizar"}), 400
    vals.append(bid)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE pago_bank_accounts SET " + ", ".join(sets) + " WHERE id=%s", vals)
            if cur.rowcount != 1:
                conn.rollback()
                return jsonify({"error": "Cuenta no encontrada"}), 404
        conn.commit()
        return jsonify({"ok": True}), 200
    except Exception:
        conn.rollback()
        log.exception("Error actualizando cuenta bancaria")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


# ---------------------------------------------------------------------------
# Clientes
# ---------------------------------------------------------------------------
@app.route("/api/pago/clientes", methods=["GET"])
@require_auth(STAFF)
def api_customers_list():
    q = (request.args.get("q") or "").strip()
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if q:
                cur.execute("SELECT * FROM pago_customers WHERE name ILIKE %s OR doc_number ILIKE %s "
                            "OR email ILIKE %s ORDER BY name LIMIT 200",
                            (f"%{q}%", f"%{q}%", f"%{q}%"))
            else:
                cur.execute("SELECT * FROM pago_customers ORDER BY created_at DESC LIMIT 200")
            return jsonify({"customers": [_dec(r) for r in cur.fetchall()]}), 200
    finally:
        put_db(conn)


@app.route("/api/pago/clientes", methods=["POST"])
@require_auth(STAFF)
def api_customers_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "El nombre es requerido"}), 400
    doc_type = (data.get("doc_type") or "cedula").strip()
    if doc_type not in ("cedula", "ruc", "pasaporte", "id_extranjera"):
        return jsonify({"error": "Tipo de documento invalido"}), 400
    doc_number = (data.get("doc_number") or "").strip() or None
    if doc_number and doc_type in ("cedula", "ruc") and not validar_documento(doc_type, doc_number):
        return jsonify({"error": f"{doc_type.upper()} invalido (digito verificador)"}), 400
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO pago_customers (doc_type,doc_number,name,email,phone,country,address,notes,created_by) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (doc_type, doc_number, name, data.get("email"), data.get("phone"),
                 (data.get("country") or "EC").upper()[:2], data.get("address"), data.get("notes"),
                 request.current_user["user_id"]))
            cid = cur.fetchone()[0]
        conn.commit()
        log_audit(request.current_user["user_id"], "CUSTOMER_CREATED", "Customer", cid,
                  {"name": name}, _client_ip())
        return jsonify({"id": str(cid)}), 201
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Ya existe un cliente con ese documento"}), 409
    except Exception:
        conn.rollback()
        log.exception("Error creando cliente")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/pago/clientes/<cid>", methods=["PUT"])
@require_auth(STAFF)
def api_customers_update(cid):
    data = request.get_json(silent=True) or {}
    if data.get("doc_number") and data.get("doc_type") in ("cedula", "ruc") \
            and not validar_documento(data["doc_type"], data["doc_number"]):
        return jsonify({"error": "Documento invalido (digito verificador)"}), 400
    sets, vals = [], []
    for field in ("doc_type", "doc_number", "name", "email", "phone", "country", "address", "notes"):
        if field in data:
            sets.append(f"{field}=%s")
            vals.append((data[field] or None))
    if "is_active" in data:
        sets.append("is_active=%s")
        vals.append(bool(data["is_active"]))
    if not sets:
        return jsonify({"error": "Nada que actualizar"}), 400
    vals.append(cid)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE pago_customers SET " + ", ".join(sets) + " WHERE id=%s", vals)
            if cur.rowcount != 1:
                conn.rollback()
                return jsonify({"error": "Cliente no encontrado"}), 404
        conn.commit()
        return jsonify({"ok": True}), 200
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Ya existe un cliente con ese documento"}), 409
    except Exception:
        conn.rollback()
        log.exception("Error actualizando cliente")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


# ---------------------------------------------------------------------------
# Cobros (charges) + enlaces
# ---------------------------------------------------------------------------
def _charge_json(row):
    out = _dec(row)
    out["link_url"] = link_url(row["link_token"])
    out["link_state"] = link_state(row["status"], row.get("link_expires_at"))
    return out


@app.route("/api/pago/cobros", methods=["GET"])
@require_auth(STAFF)
def api_charges_list():
    status = (request.args.get("status") or "").strip()
    q = (request.args.get("q") or "").strip()
    where, vals = [], []
    if status:
        where.append("ch.status=%s")
        vals.append(status)
    if q:
        where.append("(ch.code ILIKE %s OR ch.concept ILIKE %s OR cu.name ILIKE %s)")
        vals += [f"%{q}%"] * 3
    sql = ("SELECT ch.*, cu.name AS customer_name, "
           "(ch.status='pendiente' AND ch.due_date IS NOT NULL AND ch.due_date < CURRENT_DATE) AS vencido "
           "FROM pago_charges ch JOIN pago_customers cu ON cu.id=ch.customer_id ")
    if where:
        sql += "WHERE " + " AND ".join(where) + " "
    sql += "ORDER BY ch.created_at DESC LIMIT 300"
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, vals)
            return jsonify({"charges": [_charge_json(r) for r in cur.fetchall()]}), 200
    finally:
        put_db(conn)


@app.route("/api/pago/cobros", methods=["POST"])
@require_auth(STAFF)
def api_charges_create():
    data = request.get_json(silent=True) or {}
    amount = _parse_amount(data.get("amount"))
    concept = (data.get("concept") or "").strip()
    customer_id = data.get("customer_id")
    if not customer_id or not concept or amount is None:
        return jsonify({"error": "customer_id, concept y amount (>0) son requeridos"}), 400
    methods = data.get("allowed_methods") or ["tarjeta", "transferencia"]
    if not isinstance(methods, list) or not methods or \
            not set(methods) <= {"tarjeta", "transferencia"}:
        return jsonify({"error": "allowed_methods invalido"}), 400
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id FROM pago_customers WHERE id=%s AND is_active=TRUE", (customer_id,))
            if not cur.fetchone():
                return jsonify({"error": "Cliente no encontrado o inactivo"}), 404
            expires = _default_link_expiry(cur)
            cur.execute(
                "INSERT INTO pago_charges (customer_id,concept,description,amount,due_date,"
                "link_token,link_expires_at,allowed_methods,created_by) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                (customer_id, concept, data.get("description"), amount,
                 data.get("due_date") or None, new_link_token(), expires, methods,
                 request.current_user["user_id"]))
            row = cur.fetchone()
        conn.commit()
        log_audit(request.current_user["user_id"], "CHARGE_CREATED", "Charge", row["id"],
                  {"code": row["code"], "amount": float(amount)}, _client_ip())
        out = _charge_json(row)
        out["customer_name"] = None
        return jsonify({"charge": out}), 201
    except Exception:
        conn.rollback()
        log.exception("Error creando cobro")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/pago/cobros/<chid>", methods=["GET"])
@require_auth(STAFF)
def api_charges_detail(chid):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT ch.*, cu.name AS customer_name FROM pago_charges ch "
                        "JOIN pago_customers cu ON cu.id=ch.customer_id WHERE ch.id=%s", (chid,))
            charge = cur.fetchone()
            if not charge:
                return jsonify({"error": "Cobro no encontrado"}), 404
            cur.execute("SELECT p.*, tr.id AS receipt_file_id, tr.reference AS transfer_reference "
                        "FROM pago_payments p LEFT JOIN pago_transfer_receipts tr ON tr.payment_id=p.id "
                        "WHERE p.charge_id=%s ORDER BY p.created_at DESC", (chid,))
            payments = [_dec(r) for r in cur.fetchall()]
        return jsonify({"charge": _charge_json(charge), "payments": payments}), 200
    finally:
        put_db(conn)


@app.route("/api/pago/cobros/<chid>/anular", methods=["POST"])
@require_auth(STAFF)
def api_charges_void(chid):
    reason = ((request.get_json(silent=True) or {}).get("reason") or "").strip()
    if not reason:
        return jsonify({"error": "Indique el motivo de anulacion"}), 400
    cu = request.current_user
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, status FROM pago_charges WHERE id=%s FOR UPDATE", (chid,))
            charge = cur.fetchone()
            if not charge:
                return jsonify({"error": "Cobro no encontrado"}), 404
            if not can_transition("charge", charge["status"], "anulado"):
                return jsonify({"error": f"No se puede anular un cobro '{charge['status']}'"}), 409
            # Rechaza pagos publicos que quedaron en revision.
            cur.execute("UPDATE pago_payments SET status='rechazado', review_note='Cobro anulado', "
                        "reviewed_by=%s, reviewed_at=NOW(), updated_at=NOW() "
                        "WHERE charge_id=%s AND status IN ('iniciado','en_revision')",
                        (cu["user_id"], chid))
            _set_charge_status(cur, chid, charge["status"], "anulado")
            cur.execute("UPDATE pago_charges SET anulado_by=%s, anulado_at=NOW(), anulado_reason=%s "
                        "WHERE id=%s", (cu["user_id"], reason, chid))
        conn.commit()
        log_audit(cu["user_id"], "CHARGE_VOIDED", "Charge", chid, {"reason": reason}, _client_ip())
        return jsonify({"ok": True}), 200
    except ValueError as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 409
    except Exception:
        conn.rollback()
        log.exception("Error anulando cobro")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/pago/cobros/<chid>/link", methods=["POST"])
@require_auth(STAFF)
def api_charges_relink(chid):
    """Regenera el enlace (invalida el anterior) y renueva su expiracion."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT status FROM pago_charges WHERE id=%s", (chid,))
            charge = cur.fetchone()
            if not charge:
                return jsonify({"error": "Cobro no encontrado"}), 404
            if charge["status"] not in ("pendiente", "en_revision"):
                return jsonify({"error": "Solo cobros pendientes pueden regenerar enlace"}), 409
            token = new_link_token()
            cur.execute("UPDATE pago_charges SET link_token=%s, link_expires_at=%s, updated_at=NOW() "
                        "WHERE id=%s", (token, _default_link_expiry(cur), chid))
        conn.commit()
        log_audit(request.current_user["user_id"], "CHARGE_RELINK", "Charge", chid, None, _client_ip())
        return jsonify({"link_url": link_url(token)}), 200
    except Exception:
        conn.rollback()
        log.exception("Error regenerando enlace")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


# ---------------------------------------------------------------------------
# Pagos (staff)
# ---------------------------------------------------------------------------
def _payments_query(args):
    where, vals = [], []
    if args.get("status"):
        where.append("p.status=%s")
        vals.append(args["status"])
    if args.get("method"):
        where.append("p.method=%s")
        vals.append(args["method"])
    if args.get("desde"):
        where.append("p.created_at >= %s")
        vals.append(args["desde"])
    if args.get("hasta"):
        where.append("p.created_at < (%s::date + 1)")
        vals.append(args["hasta"])
    if args.get("q"):
        where.append("(ch.code ILIKE %s OR cu.name ILIKE %s OR p.receipt_number ILIKE %s)")
        vals += [f"%{args['q']}%"] * 3
    sql = ("SELECT p.*, ch.code AS charge_code, ch.concept, cu.name AS customer_name "
           "FROM pago_payments p JOIN pago_charges ch ON ch.id=p.charge_id "
           "JOIN pago_customers cu ON cu.id=ch.customer_id ")
    if where:
        sql += "WHERE " + " AND ".join(where) + " "
    sql += "ORDER BY p.created_at DESC LIMIT 500"
    return sql, vals


@app.route("/api/pago/pagos", methods=["GET"])
@require_auth(STAFF)
def api_payments_list():
    sql, vals = _payments_query(request.args)
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, vals)
            return jsonify({"payments": [_dec(r) for r in cur.fetchall()]}), 200
    finally:
        put_db(conn)


@app.route("/api/pago/pagos", methods=["POST"])
@require_auth(STAFF)
def api_payments_manual():
    """Registra un pago presencial (efectivo o cheque) sobre un cobro pendiente."""
    data = request.get_json(silent=True) or {}
    method = data.get("method")
    if method not in ("efectivo", "cheque"):
        return jsonify({"error": "method debe ser efectivo o cheque"}), 400
    cu = request.current_user
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM pago_charges WHERE id=%s FOR UPDATE", (data.get("charge_id"),))
            charge = cur.fetchone()
            if not charge:
                return jsonify({"error": "Cobro no encontrado"}), 404
            if charge["status"] != "pendiente":
                return jsonify({"error": f"El cobro esta '{charge['status']}', no pendiente"}), 409
            receipt = _next_receipt(cur)
            cur.execute(
                "INSERT INTO pago_payments (charge_id,method,amount,currency,status,receipt_number,"
                "review_note,created_by) VALUES (%s,%s,%s,%s,'aprobado',%s,%s,%s) RETURNING id",
                (charge["id"], method, charge["amount"], charge["currency"], receipt,
                 (data.get("note") or None), cu["user_id"]))
            pid = cur.fetchone()["id"]
            _set_charge_status(cur, charge["id"], "pendiente", "pagado")
        conn.commit()
        log_audit(cu["user_id"], "PAYMENT_MANUAL", "Payment", pid,
                  {"method": method, "charge": charge["code"], "receipt": receipt}, _client_ip())
        return jsonify({"id": str(pid), "receipt_number": receipt}), 201
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Este cobro ya tiene un pago exitoso"}), 409
    except ValueError as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 409
    except Exception:
        conn.rollback()
        log.exception("Error registrando pago manual")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


def _load_payment(cur, pid, lock=False):
    cur.execute("SELECT p.*, ch.code AS charge_code, ch.status AS charge_status "
                "FROM pago_payments p JOIN pago_charges ch ON ch.id=p.charge_id "
                "WHERE p.id=%s" + (" FOR UPDATE OF p, ch" if lock else ""), (pid,))
    return cur.fetchone()


@app.route("/api/pago/pagos/<pid>/aprobar", methods=["POST"])
@require_auth(ADMINS)
def api_payments_approve(pid):
    """Conciliacion: aprueba una transferencia en revision (solo admin: quien
    cobra no se auto-aprueba)."""
    cu = request.current_user
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            p = _load_payment(cur, pid, lock=True)
            if not p:
                return jsonify({"error": "Pago no encontrado"}), 404
            if p["method"] != "transferencia" or p["status"] != "en_revision":
                return jsonify({"error": "Solo transferencias en revision se aprueban"}), 409
            receipt = _next_receipt(cur)
            cur.execute("UPDATE pago_payments SET status='aprobado', receipt_number=%s, "
                        "reviewed_by=%s, reviewed_at=NOW(), updated_at=NOW() WHERE id=%s",
                        (receipt, cu["user_id"], pid))
            _set_charge_status(cur, p["charge_id"], p["charge_status"], "pagado")
        conn.commit()
        log_audit(cu["user_id"], "TRANSFER_APPROVED", "Payment", pid,
                  {"charge": p["charge_code"], "receipt": receipt}, _client_ip())
        return jsonify({"ok": True, "receipt_number": receipt}), 200
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Este cobro ya tiene un pago exitoso"}), 409
    except ValueError as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 409
    except Exception:
        conn.rollback()
        log.exception("Error aprobando transferencia")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/pago/pagos/<pid>/rechazar", methods=["POST"])
@require_auth(ADMINS)
def api_payments_reject(pid):
    motivo = ((request.get_json(silent=True) or {}).get("motivo") or "").strip()
    if not motivo:
        return jsonify({"error": "Indique el motivo del rechazo"}), 400
    cu = request.current_user
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            p = _load_payment(cur, pid, lock=True)
            if not p:
                return jsonify({"error": "Pago no encontrado"}), 404
            if p["status"] != "en_revision":
                return jsonify({"error": "Solo pagos en revision se rechazan"}), 409
            cur.execute("UPDATE pago_payments SET status='rechazado', review_note=%s, "
                        "reviewed_by=%s, reviewed_at=NOW(), updated_at=NOW() WHERE id=%s",
                        (motivo, cu["user_id"], pid))
            # El cobro vuelve a pendiente: el cliente puede reintentar con el mismo enlace.
            if p["charge_status"] == "en_revision":
                _set_charge_status(cur, p["charge_id"], "en_revision", "pendiente")
        conn.commit()
        log_audit(cu["user_id"], "TRANSFER_REJECTED", "Payment", pid,
                  {"charge": p["charge_code"], "motivo": motivo}, _client_ip())
        return jsonify({"ok": True}), 200
    except ValueError as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 409
    except Exception:
        conn.rollback()
        log.exception("Error rechazando pago")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/pago/pagos/<pid>/reembolsar", methods=["POST"])
@require_auth(ADMINS)
def api_payments_refund(pid):
    note = ((request.get_json(silent=True) or {}).get("note") or "").strip()
    cu = request.current_user
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            p = _load_payment(cur, pid, lock=True)
            if not p:
                return jsonify({"error": "Pago no encontrado"}), 404
            if p["status"] != "aprobado":
                return jsonify({"error": "Solo pagos aprobados se reembolsan"}), 409
            refund_ref = None
            if p["method"] == "tarjeta":
                if not known_gateway(p["gateway"] or ""):
                    return jsonify({"error": f"Gateway '{p['gateway']}' no disponible"}), 400
                try:
                    # PayPal (flujo orden/captura): el reembolso usa el id de CAPTURA.
                    res = get_gateway(p["gateway"]).refund(p.get("gateway_capture_ref") or p["gateway_ref"])
                except GatewayError as e:
                    conn.rollback()
                    return jsonify({"error": f"La pasarela no respondio: {e}"}), 502
                if not res.ok:
                    conn.rollback()
                    return jsonify({"error": res.message or "La pasarela rechazo el reembolso"}), 409
                refund_ref = res.gateway_ref
            elif not note:
                return jsonify({"error": "Para reembolso manual indique una nota"}), 400
            cur.execute("UPDATE pago_payments SET status='reembolsado', refund_ref=%s, "
                        "refunded_by=%s, refunded_at=NOW(), review_note=COALESCE(%s,review_note), "
                        "updated_at=NOW() WHERE id=%s",
                        (refund_ref, cu["user_id"], note or None, pid))
            _set_charge_status(cur, p["charge_id"], p["charge_status"], "reembolsado")
        conn.commit()
        log_audit(cu["user_id"], "PAYMENT_REFUNDED", "Payment", pid,
                  {"charge": p["charge_code"], "refund_ref": refund_ref, "note": note}, _client_ip())
        return jsonify({"ok": True}), 200
    except ValueError as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 409
    except Exception:
        conn.rollback()
        log.exception("Error reembolsando pago")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/pago/pagos/<pid>/anular", methods=["POST"])
@require_auth(ADMINS)
def api_payments_void(pid):
    """Anula un pago efectivo/cheque registrado por error de digitacion."""
    note = ((request.get_json(silent=True) or {}).get("note") or "").strip()
    if not note:
        return jsonify({"error": "Indique el motivo de anulacion"}), 400
    cu = request.current_user
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            p = _load_payment(cur, pid, lock=True)
            if not p:
                return jsonify({"error": "Pago no encontrado"}), 404
            if p["method"] not in ("efectivo", "cheque") or p["status"] != "aprobado":
                return jsonify({"error": "Solo pagos efectivo/cheque aprobados se anulan"}), 409
            cur.execute("UPDATE pago_payments SET status='anulado', review_note=%s, "
                        "reviewed_by=%s, reviewed_at=NOW(), updated_at=NOW() WHERE id=%s",
                        (note, cu["user_id"], pid))
            # pagado -> pendiente no es transicion normal del cobro: es correccion
            # de un error de digitacion, y queda auditada.
            cur.execute("UPDATE pago_charges SET status='pendiente', updated_at=NOW() "
                        "WHERE id=%s AND status='pagado'", (p["charge_id"],))
        conn.commit()
        log_audit(cu["user_id"], "PAYMENT_VOIDED", "Payment", pid,
                  {"charge": p["charge_code"], "note": note}, _client_ip())
        return jsonify({"ok": True}), 200
    except Exception:
        conn.rollback()
        log.exception("Error anulando pago")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/pago/conciliacion", methods=["GET"])
@require_auth(STAFF)
def api_reconciliation_list():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT p.id, p.amount, p.currency, p.payer_name, p.payer_email, p.created_at, "
                "ch.code AS charge_code, ch.concept, cu.name AS customer_name, "
                "tr.id AS receipt_file_id, tr.reference, tr.bank_name, tr.transfer_date, "
                "tr.original_filename "
                "FROM pago_payments p "
                "JOIN pago_charges ch ON ch.id=p.charge_id "
                "JOIN pago_customers cu ON cu.id=ch.customer_id "
                "LEFT JOIN pago_transfer_receipts tr ON tr.payment_id=p.id "
                "WHERE p.status='en_revision' ORDER BY p.created_at")
            return jsonify({"pending": [_dec(r) for r in cur.fetchall()]}), 200
    finally:
        put_db(conn)


@app.route("/api/pago/comprobantes/<rid>")
@require_auth(STAFF)
def api_receipt_file(rid):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM pago_transfer_receipts WHERE id=%s", (rid,))
            row = cur.fetchone()
        if not row:
            return jsonify({"error": "Comprobante no encontrado"}), 404
        path = os.path.normpath(os.path.join(UPLOAD_DIR, row["file_path"]))
        if not path.startswith(UPLOAD_DIR + os.sep) or not os.path.isfile(path):
            return jsonify({"error": "Archivo no disponible"}), 404
        return send_file(path, mimetype=row["mime_type"], as_attachment=True,
                         download_name=f"comprobante-{rid}.{row['file_path'].rsplit('.', 1)[-1]}")
    finally:
        put_db(conn)


# ---------------------------------------------------------------------------
# Recibo PDF + export Excel
# ---------------------------------------------------------------------------
def _receipt_pdf_bytes(charge, payment, config):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas as rl_canvas

    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    y = h - 25 * mm
    c.setFont("Helvetica-Bold", 15)
    c.drawString(20 * mm, y, config.get("company_name") or "Recibo de pago")
    c.setFont("Helvetica", 9)
    for line in filter(None, [
            ("RUC: " + config["company_ruc"]) if config.get("company_ruc") else None,
            config.get("company_address"),
            " · ".join(filter(None, [config.get("company_phone"), config.get("company_email")]))]):
        y -= 5 * mm
        c.drawString(20 * mm, y, line)
    y -= 12 * mm
    c.setFont("Helvetica-Bold", 13)
    c.drawString(20 * mm, y, f"RECIBO DE PAGO  {payment.get('receipt_number') or ''}")
    if (payment.get("gateway") or "") == "sandbox":
        c.setFont("Helvetica-Bold", 11)
        c.setFillColorRGB(0.8, 0.1, 0.1)
        c.drawRightString(w - 20 * mm, y, "PRUEBA — SIN VALOR")
        c.setFillColorRGB(0, 0, 0)
    y -= 10 * mm
    c.setFont("Helvetica", 10)
    fecha = payment.get("reviewed_at") or payment.get("created_at")
    rows = [
        ("Fecha", str(fecha)[:19] if fecha else ""),
        ("Cobro", f"{charge.get('code')} — {charge.get('concept')}"),
        ("Cliente", charge.get("customer_name") or ""),
        ("Metodo", payment.get("method") or ""),
    ]
    if payment.get("method") == "tarjeta":
        tarjeta = " ".join(filter(None, [payment.get("card_brand"),
                                         ("**** " + payment["card_last4"]) if payment.get("card_last4") else ""]))
        rows.append(("Tarjeta", tarjeta or "-"))
        rows.append(("Referencia", payment.get("gateway_ref") or "-"))
    for label, value in rows:
        c.setFont("Helvetica-Bold", 10)
        c.drawString(20 * mm, y, label + ":")
        c.setFont("Helvetica", 10)
        c.drawString(55 * mm, y, str(value)[:90])
        y -= 7 * mm
    y -= 4 * mm
    c.setFont("Helvetica-Bold", 14)
    c.drawString(20 * mm, y, f"TOTAL PAGADO: {payment.get('currency','USD')} {float(payment['amount']):.2f}")
    if payment.get("status") == "reembolsado":
        y -= 8 * mm
        c.setFont("Helvetica-Bold", 11)
        c.setFillColorRGB(0.8, 0.1, 0.1)
        c.drawString(20 * mm, y, "PAGO REEMBOLSADO")
        c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 7)
    c.drawString(20 * mm, 15 * mm, "Documento interno de constancia de pago. No reemplaza a la factura.")
    c.showPage()
    c.save()
    buf.seek(0)
    return buf


def _find_success_payment(cur, charge_id):
    cur.execute("SELECT * FROM pago_payments WHERE charge_id=%s "
                "AND status IN ('aprobado','reembolsado') LIMIT 1", (charge_id,))
    return cur.fetchone()


@app.route("/api/pago/pagos/<pid>/recibo.pdf")
@require_auth(STAFF)
def api_payment_receipt_pdf(pid):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT p.*, ch.code, ch.concept, ch.customer_id, cu.name AS customer_name "
                        "FROM pago_payments p JOIN pago_charges ch ON ch.id=p.charge_id "
                        "JOIN pago_customers cu ON cu.id=ch.customer_id WHERE p.id=%s", (pid,))
            p = cur.fetchone()
            if not p or p["status"] not in ("aprobado", "reembolsado"):
                return jsonify({"error": "No hay recibo para este pago"}), 404
            config = get_config(cur)
        buf = _receipt_pdf_bytes(p, p, config)
        return send_file(buf, mimetype="application/pdf",
                         download_name=f"{p.get('receipt_number') or 'recibo'}.pdf")
    finally:
        put_db(conn)


@app.route("/api/pago/pagos/export.xlsx")
@require_auth(STAFF)
def api_payments_export():
    from openpyxl import Workbook
    sql, vals = _payments_query(request.args)
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, vals)
            rows = cur.fetchall()
    finally:
        put_db(conn)
    wb = Workbook()
    ws = wb.active
    ws.title = "Pagos"
    ws.append(["Fecha", "Recibo", "Cobro", "Cliente", "Concepto", "Metodo", "Estado",
               "Monto", "Moneda", "Referencia", "Pagador", "Nota"])
    for r in rows:
        ws.append([str(r["created_at"])[:19], r.get("receipt_number"), r.get("charge_code"),
                   r.get("customer_name"), r.get("concept"), r.get("method"), r.get("status"),
                   float(r["amount"]), r.get("currency"), r.get("gateway_ref"),
                   r.get("payer_name"), r.get("review_note")])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return send_file(buf, download_name="pagos.xlsx", mimetype=
                     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


# ---------------------------------------------------------------------------
# Dashboard + auditoria
# ---------------------------------------------------------------------------
@app.route("/api/pago/dashboard")
@require_auth(STAFF)
def api_dashboard():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT COALESCE(SUM(amount),0) AS total, COUNT(*) AS n FROM pago_payments "
                        "WHERE status='aprobado' AND created_at >= date_trunc('month', NOW())")
            mes = cur.fetchone()
            cur.execute("SELECT COALESCE(SUM(amount),0) AS total, COUNT(*) AS n FROM pago_charges "
                        "WHERE status='pendiente'")
            pend = cur.fetchone()
            cur.execute("SELECT COUNT(*) AS n FROM pago_payments WHERE status='en_revision'")
            rev = cur.fetchone()
            cur.execute("SELECT COUNT(*) AS n FROM pago_charges WHERE status='pendiente' "
                        "AND due_date IS NOT NULL AND due_date < CURRENT_DATE")
            venc = cur.fetchone()
            cur.execute("SELECT method, COALESCE(SUM(amount),0) AS total, COUNT(*) AS n "
                        "FROM pago_payments WHERE status='aprobado' "
                        "AND created_at >= date_trunc('month', NOW()) GROUP BY method")
            por_metodo = [_dec(r) for r in cur.fetchall()]
            cur.execute("SELECT p.created_at, p.amount, p.method, p.status, p.receipt_number, "
                        "ch.code AS charge_code, cu.name AS customer_name "
                        "FROM pago_payments p JOIN pago_charges ch ON ch.id=p.charge_id "
                        "JOIN pago_customers cu ON cu.id=ch.customer_id "
                        "ORDER BY p.created_at DESC LIMIT 8")
            ultimos = [_dec(r) for r in cur.fetchall()]
        return jsonify({
            "cobrado_mes": {"total": float(mes["total"]), "n": mes["n"]},
            "pendiente": {"total": float(pend["total"]), "n": pend["n"]},
            "en_revision": rev["n"], "vencidos": venc["n"],
            "por_metodo": por_metodo, "ultimos": ultimos,
        }), 200
    finally:
        put_db(conn)


@app.route("/api/pago/auditoria")
@require_auth(["super_admin"])
def api_audit_list():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT a.*, u.username FROM pago_audit_log a "
                        "LEFT JOIN pago_users u ON u.id=a.user_id "
                        "ORDER BY a.created_at DESC LIMIT 200")
            return jsonify({"audit": [_dec(r) for r in cur.fetchall()]}), 200
    finally:
        put_db(conn)


# ---------------------------------------------------------------------------
# Checkout publico (enlace de pago)
# ---------------------------------------------------------------------------
def _public_context(cur, charge):
    config = get_config(cur)
    cur.execute("SELECT bank_name,account_type,account_number,holder_name,holder_doc,swift_bic,"
                "extra_instructions FROM pago_bank_accounts WHERE is_active=TRUE "
                "ORDER BY display_order, created_at")
    banks = [dict(r) for r in cur.fetchall()]
    return {"config": config, "banks": banks,
            "charge": charge, "state": link_state(charge["status"], charge.get("link_expires_at")),
            "gateway": os.environ.get("GATEWAY", "sandbox"),
            "paypal_client_id": os.environ.get("PAYPAL_CLIENT_ID", "")}


@app.route("/pay/<token>")
@rate_limit(30, 60)
def public_pay_page(token):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            charge = _load_charge_by_token(cur, token)
            if not charge:
                return render_template("pay.html", state="invalid", charge=None,
                                       config={}, banks=[], gateway=""), 404
            ctx = _public_context(cur, charge)
        return render_template("pay.html", **ctx)
    finally:
        put_db(conn)


@app.route("/api/public/pay/<token>/card", methods=["POST"])
@rate_limit(10, 60)
def public_pay_card(token):
    data = request.get_json(silent=True) or {}
    card_token = (data.get("card_token") or "").strip()
    if not card_token:
        return jsonify({"error": "card_token requerido"}), 400
    ip = _client_ip()
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            charge = _load_charge_by_token(cur, token)
            if not charge:
                return jsonify({"error": "Enlace no valido"}), 404
            state = link_state(charge["status"], charge.get("link_expires_at"))
            if state != "activo":
                return jsonify({"error": "Este enlace ya no admite pagos", "state": state}), 409
            if "tarjeta" not in (charge["allowed_methods"] or []):
                return jsonify({"error": "Este cobro no acepta tarjeta"}), 409
            # Limite de negocio (preciso, en BD): 5 intentos de tarjeta / 15 min por cobro.
            cur.execute("SELECT COUNT(*) AS n FROM pago_payments WHERE charge_id=%s AND method='tarjeta' "
                        "AND created_at > NOW() - INTERVAL '15 minutes'", (charge["id"],))
            if cur.fetchone()["n"] >= 5:
                return jsonify({"error": "Demasiados intentos. Espere unos minutos."}), 429
            cur.execute(
                "INSERT INTO pago_payments (charge_id,method,amount,currency,status,gateway,"
                "payer_name,payer_email,payer_ip) VALUES (%s,'tarjeta',%s,%s,'iniciado',%s,%s,%s,%s) "
                "RETURNING id",
                (charge["id"], charge["amount"], charge["currency"],
                 os.environ.get("GATEWAY", "sandbox"),
                 (data.get("payer_name") or "").strip()[:120] or None,
                 (data.get("payer_email") or "").strip()[:200] or None, ip))
            pid = cur.fetchone()["id"]
        conn.commit()   # el intento queda registrado aunque la pasarela falle

        gw = get_gateway()
        try:
            res = gw.create_charge(amount=charge["amount"], currency=charge["currency"],
                                   card_token=card_token, description=charge["concept"],
                                   payer_email=data.get("payer_email") or "",
                                   metadata={"charge_code": charge["code"]})
        except GatewayError as e:
            with conn.cursor() as cur:
                cur.execute("UPDATE pago_payments SET error_message=%s, updated_at=NOW() WHERE id=%s",
                            (str(e), pid))
            conn.commit()
            return jsonify({"error": "No se pudo contactar la pasarela. Intente de nuevo."}), 502

        if res.ok:
            try:
                with conn.cursor() as cur:
                    receipt = _next_receipt(cur)
                    cur.execute("UPDATE pago_payments SET status='aprobado', gateway_ref=%s, "
                                "gateway_status=%s, card_brand=%s, card_last4=%s, receipt_number=%s, "
                                "updated_at=NOW() WHERE id=%s",
                                (res.gateway_ref, res.raw_status, res.card_brand, res.card_last4,
                                 receipt, pid))
                    _set_charge_status(cur, charge["id"], charge["status"], "pagado")
                conn.commit()
            except (psycopg2.errors.UniqueViolation, ValueError):
                conn.rollback()
                return jsonify({"error": "Este cobro ya fue pagado"}), 409
            log_audit(None, "CARD_PAYMENT_APPROVED", "Payment", pid,
                      {"charge": charge["code"], "gateway_ref": res.gateway_ref}, ip)
            return jsonify({"status": "aprobado", "receipt_number": receipt,
                            "recibo_url": f"/pay/{token}/recibo.pdf"}), 200

        with conn.cursor() as cur:
            cur.execute("UPDATE pago_payments SET status='rechazado', gateway_ref=%s, "
                        "gateway_status=%s, error_message=%s, updated_at=NOW() WHERE id=%s",
                        (res.gateway_ref, res.raw_status, res.message, pid))
        conn.commit()
        log_audit(None, "CARD_PAYMENT_DECLINED", "Payment", pid,
                  {"charge": charge["code"], "message": res.message}, ip)
        return jsonify({"status": "rechazado",
                        "message": res.message or "Tarjeta rechazada"}), 200
    except Exception:
        conn.rollback()
        log.exception("Error en pago con tarjeta")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/public/pay/<token>/paypal/order", methods=["POST"])
@rate_limit(10, 60)
def public_paypal_order(token):
    """Paso 1 del flujo PayPal: crea la orden que el SDK JS presenta al pagador."""
    gw = get_gateway()
    if not getattr(gw, "supports_orders", False):
        return jsonify({"error": "PayPal no esta habilitado"}), 409
    data = request.get_json(silent=True) or {}
    ip = _client_ip()
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            charge = _load_charge_by_token(cur, token)
            if not charge:
                return jsonify({"error": "Enlace no valido"}), 404
            state = link_state(charge["status"], charge.get("link_expires_at"))
            if state != "activo":
                return jsonify({"error": "Este enlace ya no admite pagos", "state": state}), 409
            if "tarjeta" not in (charge["allowed_methods"] or []):
                return jsonify({"error": "Este cobro no acepta tarjeta/PayPal"}), 409
            cur.execute("SELECT COUNT(*) AS n FROM pago_payments WHERE charge_id=%s AND method='tarjeta' "
                        "AND created_at > NOW() - INTERVAL '15 minutes'", (charge["id"],))
            if cur.fetchone()["n"] >= 5:
                return jsonify({"error": "Demasiados intentos. Espere unos minutos."}), 429
            cur.execute(
                "INSERT INTO pago_payments (charge_id,method,amount,currency,status,gateway,"
                "payer_name,payer_email,payer_ip) VALUES (%s,'tarjeta',%s,%s,'iniciado',%s,%s,%s,%s) "
                "RETURNING id",
                (charge["id"], charge["amount"], charge["currency"], gw.name,
                 (data.get("payer_name") or "").strip()[:120] or None,
                 (data.get("payer_email") or "").strip()[:200] or None, ip))
            pid = cur.fetchone()["id"]
        conn.commit()   # el intento queda registrado aunque PayPal falle

        try:
            res = gw.create_order(amount=charge["amount"], currency=charge["currency"],
                                  description=charge["concept"], reference=str(pid))
        except GatewayError as e:
            with conn.cursor() as cur:
                cur.execute("UPDATE pago_payments SET error_message=%s, updated_at=NOW() WHERE id=%s",
                            (str(e), pid))
            conn.commit()
            return jsonify({"error": "No se pudo contactar a PayPal. Intente de nuevo."}), 502

        with conn.cursor() as cur:
            cur.execute("UPDATE pago_payments SET gateway_ref=%s, gateway_status=%s, "
                        "updated_at=NOW() WHERE id=%s", (res.gateway_ref, res.raw_status, pid))
        conn.commit()
        return jsonify({"order_id": res.gateway_ref}), 200
    except Exception:
        conn.rollback()
        log.exception("Error creando orden PayPal")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/public/pay/<token>/paypal/capture", methods=["POST"])
@rate_limit(15, 60)
def public_paypal_capture(token):
    """Paso 2 del flujo PayPal: el pagador ya aprobo; capturamos el dinero."""
    gw = get_gateway()
    if not getattr(gw, "supports_orders", False):
        return jsonify({"error": "PayPal no esta habilitado"}), 409
    order_id = ((request.get_json(silent=True) or {}).get("order_id") or "").strip()
    if not order_id:
        return jsonify({"error": "order_id requerido"}), 400
    ip = _client_ip()
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            charge = _load_charge_by_token(cur, token)
            if not charge:
                return jsonify({"error": "Enlace no valido"}), 404
            cur.execute("SELECT * FROM pago_payments WHERE charge_id=%s AND gateway_ref=%s "
                        "AND method='tarjeta' AND status='iniciado'", (charge["id"], order_id))
            payment = cur.fetchone()
            if not payment:
                return jsonify({"error": "Orden no encontrada o ya procesada"}), 404
            if link_state(charge["status"], charge.get("link_expires_at")) != "activo":
                return jsonify({"error": "Este enlace ya no admite pagos"}), 409

        try:
            res = gw.capture_order(order_id)
        except GatewayError as e:
            with conn.cursor() as cur:
                cur.execute("UPDATE pago_payments SET error_message=%s, updated_at=NOW() WHERE id=%s",
                            (str(e), payment["id"]))
            conn.commit()
            return jsonify({"error": "No se pudo confirmar con PayPal. Intente de nuevo."}), 502

        if res.ok:
            capture_id = res.extra.get("capture_id") or ""
            try:
                with conn.cursor() as cur:
                    receipt = _next_receipt(cur)
                    cur.execute("UPDATE pago_payments SET status='aprobado', gateway_status=%s, "
                                "gateway_capture_ref=%s, card_brand=%s, card_last4=%s, "
                                "payer_email=COALESCE(payer_email,%s), receipt_number=%s, "
                                "updated_at=NOW() WHERE id=%s",
                                (res.raw_status, capture_id, res.card_brand, res.card_last4,
                                 res.extra.get("payer_email") or None, receipt, payment["id"]))
                    _set_charge_status(cur, charge["id"], charge["status"], "pagado")
                conn.commit()
            except (psycopg2.errors.UniqueViolation, ValueError):
                # El cobro ya tenia un pago exitoso pero PayPal YA capturo el
                # dinero: se reembolsa de inmediato para no cobrar dos veces.
                conn.rollback()
                try:
                    gw.refund(capture_id or order_id)
                    note = "duplicado: captura reembolsada automaticamente"
                except GatewayError:
                    note = "DUPLICADO SIN REEMBOLSAR: reembolsar a mano en PayPal"
                    log.error("PayPal: captura duplicada %s sin reembolso automatico", capture_id)
                with conn.cursor() as cur:
                    cur.execute("UPDATE pago_payments SET status='rechazado', error_message=%s, "
                                "gateway_capture_ref=%s, updated_at=NOW() WHERE id=%s",
                                (note, capture_id, payment["id"]))
                conn.commit()
                log_audit(None, "PAYPAL_DUPLICATE_CAPTURE", "Payment", payment["id"],
                          {"charge": charge["code"], "note": note}, ip)
                return jsonify({"error": "Este cobro ya fue pagado"}), 409
            log_audit(None, "CARD_PAYMENT_APPROVED", "Payment", payment["id"],
                      {"charge": charge["code"], "gateway_ref": order_id,
                       "capture": capture_id, "gateway": gw.name}, ip)
            return jsonify({"status": "aprobado", "receipt_number": receipt,
                            "recibo_url": f"/pay/{token}/recibo.pdf"}), 200

        retry = bool(res.extra.get("retry"))
        with conn.cursor() as cur:
            if retry:
                # INSTRUMENT_DECLINED: el SDK reintenta con LA MISMA orden, asi
                # que el pago sigue 'iniciado' para que la proxima captura funcione.
                cur.execute("UPDATE pago_payments SET gateway_status=%s, error_message=%s, "
                            "updated_at=NOW() WHERE id=%s",
                            (res.raw_status, res.message, payment["id"]))
            else:
                cur.execute("UPDATE pago_payments SET status='rechazado', gateway_status=%s, "
                            "error_message=%s, updated_at=NOW() WHERE id=%s",
                            (res.raw_status, res.message, payment["id"]))
        conn.commit()
        log_audit(None, "CARD_PAYMENT_DECLINED", "Payment", payment["id"],
                  {"charge": charge["code"], "message": res.message, "gateway": gw.name,
                   "retry": retry}, ip)
        return jsonify({"status": "rechazado", "message": res.message or "PayPal rechazo el pago",
                        "retry": retry}), 200
    except Exception:
        conn.rollback()
        log.exception("Error capturando orden PayPal")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/api/public/pay/<token>/transfer", methods=["POST"])
@rate_limit(10, 60)
def public_pay_transfer(token):
    reference = (request.form.get("reference") or "").strip()
    if not reference:
        return jsonify({"error": "Indique el numero de referencia de la transferencia"}), 400
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "Adjunte el comprobante (JPG, PNG o PDF)"}), 400
    content = file.read()
    if not content:
        return jsonify({"error": "Archivo vacio"}), 400
    ok, ext_or_err, mime = validate_upload(file.filename, content[:8])
    if not ok:
        return jsonify({"error": ext_or_err}), 400
    ip = _client_ip()
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            charge = _load_charge_by_token(cur, token)
            if not charge:
                return jsonify({"error": "Enlace no valido"}), 404
            state = link_state(charge["status"], charge.get("link_expires_at"))
            if state != "activo":
                return jsonify({"error": "Este enlace ya no admite pagos", "state": state}), 409
            if "transferencia" not in (charge["allowed_methods"] or []):
                return jsonify({"error": "Este cobro no acepta transferencia"}), 409
            # Limite de negocio: 3 comprobantes / hora por cobro.
            cur.execute("SELECT COUNT(*) AS n FROM pago_transfer_receipts tr "
                        "JOIN pago_payments p ON p.id=tr.payment_id "
                        "WHERE p.charge_id=%s AND tr.uploaded_at > NOW() - INTERVAL '1 hour'",
                        (charge["id"],))
            if cur.fetchone()["n"] >= 3:
                return jsonify({"error": "Demasiados comprobantes enviados. Espere."}), 429

            fname = f"comprobantes/{uuid.uuid4()}.{ext_or_err}"
            os.makedirs(os.path.join(UPLOAD_DIR, "comprobantes"), exist_ok=True)
            with open(os.path.join(UPLOAD_DIR, fname), "wb") as fh:
                fh.write(content)

            cur.execute(
                "INSERT INTO pago_payments (charge_id,method,amount,currency,status,"
                "payer_name,payer_email,payer_ip) VALUES (%s,'transferencia',%s,%s,'en_revision',"
                "%s,%s,%s) RETURNING id",
                (charge["id"], charge["amount"], charge["currency"],
                 (request.form.get("payer_name") or "").strip()[:120] or None,
                 (request.form.get("payer_email") or "").strip()[:200] or None, ip))
            pid = cur.fetchone()["id"]
            cur.execute(
                "INSERT INTO pago_transfer_receipts (payment_id,file_path,original_filename,"
                "mime_type,size_bytes,reference,bank_name,transfer_date,uploaded_ip) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (pid, fname, file.filename[:200], mime, len(content), reference[:100],
                 (request.form.get("bank_name") or "").strip()[:100] or None,
                 request.form.get("transfer_date") or None, ip))
            if charge["status"] == "pendiente":
                _set_charge_status(cur, charge["id"], "pendiente", "en_revision")
        conn.commit()
        log_audit(None, "TRANSFER_SUBMITTED", "Payment", pid,
                  {"charge": charge["code"], "reference": reference}, ip)
        return jsonify({"status": "en_revision",
                        "message": "Comprobante recibido. Su pago sera verificado."}), 200
    except ValueError as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 409
    except Exception:
        conn.rollback()
        log.exception("Error registrando transferencia")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


@app.route("/pay/<token>/recibo.pdf")
@rate_limit(30, 60)
def public_receipt_pdf(token):
    """Recibo para el pagador: solo si el cobro esta pagado. Quien tiene el
    enlace tiene el recibo (capability del token)."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            charge = _load_charge_by_token(cur, token)
            if not charge or charge["status"] not in ("pagado", "reembolsado"):
                return jsonify({"error": "Recibo no disponible"}), 404
            payment = _find_success_payment(cur, charge["id"])
            if not payment:
                return jsonify({"error": "Recibo no disponible"}), 404
            config = get_config(cur)
        buf = _receipt_pdf_bytes(charge, payment, config)
        return send_file(buf, mimetype="application/pdf",
                         download_name=f"{payment.get('receipt_number') or 'recibo'}.pdf")
    finally:
        put_db(conn)


@app.route("/api/webhooks/<gateway>", methods=["POST"])
@rate_limit(60, 60)
def public_webhook(gateway):
    """Confirmacion asincrona de pasarelas reales (Kushki/PayPal). Idempotente
    por (gateway, external_id). El sandbox no emite webhooks."""
    if not known_gateway(gateway):
        return jsonify({"error": "Gateway desconocido"}), 404
    try:
        event = get_gateway(gateway).parse_webhook(dict(request.headers), request.get_data())
    except NotImplementedError:
        return jsonify({"error": "Este gateway no usa webhooks"}), 400
    except ValueError as e:
        log.warning("Webhook invalido de %s: %s", gateway, e)
        return jsonify({"error": "Firma invalida"}), 400
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("INSERT INTO pago_gateway_events (gateway,event_type,external_id,payload) "
                        "VALUES (%s,%s,%s,%s) ON CONFLICT (gateway, external_id) DO NOTHING "
                        "RETURNING id",
                        (gateway, event.event_type, event.external_id,
                         psycopg2.extras.Json(event.payload)))
            if not cur.fetchone():
                conn.commit()
                return jsonify({"ok": True, "duplicate": True}), 200
            cur.execute("SELECT p.*, ch.status AS charge_status FROM pago_payments p "
                        "JOIN pago_charges ch ON ch.id=p.charge_id "
                        "WHERE p.gateway=%s AND p.gateway_ref=%s FOR UPDATE OF p, ch",
                        (gateway, event.gateway_ref))
            p = cur.fetchone()
            if p and can_transition("payment", p["status"], event.status):
                receipt = _next_receipt(cur) if event.status == "aprobado" else p["receipt_number"]
                cur.execute("UPDATE pago_payments SET status=%s, gateway_status=%s, "
                            "receipt_number=COALESCE(receipt_number,%s), updated_at=NOW() WHERE id=%s",
                            (event.status, event.event_type, receipt, pid_ := p["id"]))
                if event.status == "aprobado" and p["charge_status"] in ("pendiente", "en_revision"):
                    _set_charge_status(cur, p["charge_id"], p["charge_status"], "pagado")
                elif event.status == "reembolsado" and p["charge_status"] == "pagado":
                    _set_charge_status(cur, p["charge_id"], "pagado", "reembolsado")
                cur.execute("UPDATE pago_gateway_events SET payment_id=%s "
                            "WHERE gateway=%s AND external_id=%s", (pid_, gateway, event.external_id))
        conn.commit()
        return jsonify({"ok": True}), 200
    except Exception:
        conn.rollback()
        log.exception("Error procesando webhook")
        return jsonify({"error": "Error interno"}), 500
    finally:
        put_db(conn)


# ---------------------------------------------------------------------------
# Paginas (admin)
# ---------------------------------------------------------------------------
def _page(template, page_id):
    if not _token_from_request():
        return redirect("/login")
    return render_template(template, page=page_id)


@app.route("/")
def root():
    return _page("dashboard.html", "dashboard")


@app.route("/login")
def page_login():
    return render_template("login.html")


@app.route("/cobros")
def page_charges():
    return _page("cobros.html", "cobros")


@app.route("/clientes")
def page_customers():
    return _page("clientes.html", "clientes")


@app.route("/pagos")
def page_payments():
    return _page("pagos.html", "pagos")


@app.route("/conciliacion")
def page_reconciliation():
    return _page("conciliacion.html", "conciliacion")


@app.route("/usuarios")
def page_users():
    return _page("usuarios.html", "usuarios")


@app.route("/configuracion")
def page_config():
    return _page("configuracion.html", "configuracion")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "dimed-pago"}), 200


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": f"El archivo supera el maximo de {MAX_UPLOAD_MB} MB"}), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000, debug=os.environ.get("FLASK_DEBUG") == "1")  # nosec B104

"""
Validadores de identificacion ecuatoriana (cedula, RUC) — algoritmo del digito
verificador del Registro Civil / SRI. Evita errores de transcripcion al registrar.
"""


def validar_cedula(ced):
    """Cedula ecuatoriana: 10 digitos, provincia 01-24/30, tercer digito < 6, modulo-10."""
    ced = (ced or "").strip()
    if not ced.isdigit() or len(ced) != 10:
        return False
    prov = int(ced[:2])
    if prov < 1 or (prov > 24 and prov != 30):
        return False
    if int(ced[2]) >= 6:
        return False
    total = 0
    for i in range(9):
        v = int(ced[i]) * (2 if i % 2 == 0 else 1)
        if v > 9:
            v -= 9
        total += v
    verificador = (10 - (total % 10)) % 10
    return verificador == int(ced[9])


def validar_ruc(ruc):
    """RUC ecuatoriano (13 digitos): natural (cedula+establecimiento), sociedad (mod-11) o publico."""
    ruc = (ruc or "").strip()
    if not ruc.isdigit() or len(ruc) != 13:
        return False
    prov = int(ruc[:2])
    if prov < 1 or (prov > 24 and prov != 30):
        return False
    tercero = int(ruc[2])
    if tercero < 6:  # persona natural: primeros 10 = cedula valida + establecimiento 001+
        return validar_cedula(ruc[:10]) and int(ruc[10:]) >= 1
    if tercero == 9:  # sociedad privada: modulo 11, verificador en posicion 10
        coef = [4, 3, 2, 7, 6, 5, 4, 3, 2]
        total = sum(int(ruc[i]) * coef[i] for i in range(9))
        r = total % 11
        verificador = 0 if r == 0 else 11 - r
        return verificador == int(ruc[9]) and int(ruc[10:]) >= 1
    if tercero == 6:  # entidad publica: modulo 11, verificador en posicion 9
        coef = [3, 2, 7, 6, 5, 4, 3, 2]
        total = sum(int(ruc[i]) * coef[i] for i in range(8))
        r = total % 11
        verificador = 0 if r == 0 else 11 - r
        return verificador == int(ruc[8]) and int(ruc[9:]) >= 1
    return False


def validar_documento(tipo, numero):
    """Valida segun el tipo de documento. 'pasaporte' u otros: solo formato basico."""
    numero = (numero or "").strip()
    tipo = (tipo or "cedula").lower()
    if tipo == "cedula":
        return validar_cedula(numero)
    if tipo == "ruc":
        return validar_ruc(numero)
    return len(numero) >= 5  # pasaporte: sin digito verificador, longitud minima


def validar_password(pw):
    """Politica: min 12 caracteres + al menos 3 de 4 clases (minuscula, mayuscula,
    digito, simbolo); rechaza comunes. Devuelve (ok, mensaje)."""
    pw = pw or ""
    if len(pw) < 12:
        return False, "La contrasena debe tener al menos 12 caracteres"
    clases = (any(c.islower() for c in pw) + any(c.isupper() for c in pw)
              + any(c.isdigit() for c in pw) + any(not c.isalnum() for c in pw))
    if clases < 3:
        return False, "La contrasena debe combinar al menos 3 de: minusculas, mayusculas, numeros, simbolos"
    if pw.lower() in {"contrasena123", "password1234", "administrador", "123456789012", "qwertyuiop12"}:
        return False, "La contrasena es demasiado comun"
    return True, ""

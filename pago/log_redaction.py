"""
Filtro de logging que enmascara PII/PHI (cedula, RUC, email, telefono) en los
mensajes de log. Defensa en profundidad: ningun dato sensible de paciente debe
quedar en texto plano en los logs.

Uso (tras logging.basicConfig):
    from log_redaction import install_phi_redaction
    install_phi_redaction()
"""
import logging
import re

_PATTERNS = [
    # Email primero: se enmascara entero antes que los patrones de digitos.
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), '[EMAIL]'),
    (re.compile(r'\b\d{13}\b'), '[RUC]'),     # RUC ecuatoriano: 13 digitos
    (re.compile(r'\b\d{10}\b'), '[CEDULA]'),  # cedula: 10 digitos
    (re.compile(r'(?<!\d)\+593\d{8,9}(?!\d)'), '[TEL]'),  # telefono EC internacional
]


class PhiRedactionFilter(logging.Filter):
    """Reemplaza cedula/RUC/email/telefono por marcadores en cada registro de log."""

    def filter(self, record):
        try:
            msg = record.getMessage()
            red = msg
            for rx, repl in _PATTERNS:
                red = rx.sub(repl, red)
            if red != msg:
                record.msg = red
                record.args = ()
        except Exception:
            pass
        return True


def install_phi_redaction():
    """Adjunta el filtro a todos los handlers del root logger (cubre app + librerias)."""
    flt = PhiRedactionFilter()
    for h in logging.getLogger().handlers:
        h.addFilter(flt)
    return flt

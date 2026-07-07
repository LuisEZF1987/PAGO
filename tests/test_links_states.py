"""Enlaces de pago (tokens, estados) + maquina de estados + validacion de uploads."""
from datetime import datetime, timedelta, timezone

import pago_app


class TestLinkToken:
    def test_longitud_y_unicidad(self):
        tokens = {pago_app.new_link_token() for _ in range(1000)}
        assert len(tokens) == 1000
        assert all(len(t) >= 43 for t in tokens)   # 32 bytes urlsafe → ~43 chars

    def test_link_url(self):
        assert pago_app.link_url("abc").endswith("/pay/abc")


class TestLinkState:
    NOW = datetime(2026, 7, 6, tzinfo=timezone.utc)

    def test_activo(self):
        assert pago_app.link_state("pendiente", self.NOW + timedelta(days=1), self.NOW) == "activo"
        assert pago_app.link_state("pendiente", None, self.NOW) == "activo"

    def test_vencido(self):
        assert pago_app.link_state("pendiente", self.NOW - timedelta(minutes=1), self.NOW) == "vencido"

    def test_terminales(self):
        assert pago_app.link_state("pagado", None, self.NOW) == "pagado"
        assert pago_app.link_state("reembolsado", None, self.NOW) == "pagado"
        assert pago_app.link_state("anulado", None, self.NOW) == "anulado"
        assert pago_app.link_state("en_revision", None, self.NOW) == "en_revision"

    def test_vencimiento_no_aplica_a_pagado(self):
        assert pago_app.link_state("pagado", self.NOW - timedelta(days=1), self.NOW) == "pagado"


class TestStateMachine:
    def test_transiciones_validas(self):
        assert pago_app.can_transition("charge", "pendiente", "pagado")
        assert pago_app.can_transition("charge", "en_revision", "pendiente")
        assert pago_app.can_transition("charge", "pagado", "reembolsado")
        assert pago_app.can_transition("payment", "iniciado", "aprobado")
        assert pago_app.can_transition("payment", "en_revision", "rechazado")
        assert pago_app.can_transition("payment", "aprobado", "reembolsado")

    def test_transiciones_invalidas(self):
        assert not pago_app.can_transition("charge", "anulado", "pagado")
        assert not pago_app.can_transition("charge", "reembolsado", "pendiente")
        assert not pago_app.can_transition("charge", "pagado", "pendiente")
        assert not pago_app.can_transition("payment", "rechazado", "aprobado")
        assert not pago_app.can_transition("payment", "reembolsado", "aprobado")
        assert not pago_app.can_transition("payment", "iniciado", "reembolsado")


class TestValidateUpload:
    def test_pdf_ok(self):
        ok, ext, mime = pago_app.validate_upload("comprobante.pdf", b"%PDF-1.7")
        assert ok and ext == "pdf" and mime == "application/pdf"

    def test_png_ok(self):
        ok, ext, mime = pago_app.validate_upload("foto.PNG", b"\x89PNG\r\n\x1a\n")
        assert ok and ext == "png"

    def test_jpg_ok(self):
        ok, ext, _ = pago_app.validate_upload("foto.jpeg", b"\xff\xd8\xff\xe0")
        assert ok and ext == "jpeg"

    def test_extension_prohibida(self):
        ok, err, _ = pago_app.validate_upload("virus.exe", b"MZ\x90")
        assert not ok

    def test_magic_bytes_no_coinciden(self):
        ok, err, _ = pago_app.validate_upload("finge.png", b"%PDF-1.7")
        assert not ok

    def test_sin_extension(self):
        ok, _, _ = pago_app.validate_upload("archivo", b"%PDF")
        assert not ok

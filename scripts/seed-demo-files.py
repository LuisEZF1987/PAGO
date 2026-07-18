#!/usr/bin/env python3
"""Genera los PDFs de comprobante de transferencia que referencia
scripts/seed-demo-video.sql. Ejecutar DENTRO del contenedor pago:

    docker exec dimed-pago-core python3 - < scripts/seed-demo-files.py

Idempotente: no reescribe archivos existentes.
"""
import os
from reportlab.lib.pagesizes import A5
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

UPLOAD_DIR = os.path.abspath(os.environ.get("UPLOAD_DIR", "/app/uploads"))
DEST = os.path.join(UPLOAD_DIR, "comprobantes")
os.makedirs(DEST, exist_ok=True)

DEMOS = [
    ("demo-transfer-01.pdf", "BANCO PICHINCHA", "TRX-2094817", "745.50",
     "HOSPITAL DEL VALLE HOSVALLE S.A.", "DIMED HEALTHCARE S.A.", "2100123456"),
    ("demo-transfer-02.pdf", "BANCO GUAYAQUIL", "BG-77120453", "94.50",
     "ROSA ELENA PAREDES GUAMAN", "DIMED HEALTHCARE S.A.", "0018903245"),
    ("demo-transfer-03.pdf", "BANCO PICHINCHA", "PICH-5563021", "148.75",
     "MARIA FERNANDA TORRES VACA", "DIMED HEALTHCARE S.A.", "2100123456"),
    ("demo-transfer-04.pdf", "PRODUBANCO", "PROD-1187264", "2170.00",
     "HOSPITAL DEL VALLE HOSVALLE S.A.", "DIMED HEALTHCARE S.A.", "12058764310"),
]

for fname, banco, ref, monto, ordenante, beneficiario, cuenta in DEMOS:
    path = os.path.join(DEST, fname)
    if os.path.exists(path):
        print(f"ya existe: {fname}")
        continue
    c = canvas.Canvas(path, pagesize=A5)
    w, h = A5
    c.setFillColorRGB(0.02, 0.29, 0.55)
    c.rect(0, h - 22 * mm, w, 22 * mm, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(12 * mm, h - 14 * mm, banco)
    c.setFont("Helvetica", 8)
    c.drawString(12 * mm, h - 19 * mm, "Banca electronica — Comprobante de transferencia")
    c.setFillColorRGB(0.1, 0.1, 0.1)
    y = h - 34 * mm
    rows = [
        ("Estado", "EXITOSA"),
        ("No. de referencia", ref),
        ("Monto", f"USD {monto}"),
        ("Ordenante", ordenante),
        ("Beneficiario", beneficiario),
        ("Cuenta destino", cuenta),
        ("Concepto", "PAGO DIMED-PAGO"),
    ]
    for k, v in rows:
        c.setFont("Helvetica", 8)
        c.setFillColorRGB(0.45, 0.45, 0.45)
        c.drawString(12 * mm, y, k.upper())
        c.setFont("Helvetica-Bold", 10)
        c.setFillColorRGB(0.1, 0.1, 0.1)
        c.drawString(55 * mm, y, v)
        y -= 9 * mm
    c.setFont("Helvetica", 7)
    c.setFillColorRGB(0.55, 0.55, 0.55)
    c.drawString(12 * mm, 12 * mm, "Documento generado electronicamente — demo, sin valor real.")
    c.showPage()
    c.save()
    print(f"creado: {fname}")

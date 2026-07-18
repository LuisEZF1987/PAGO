-- ============================================================================
-- Dimed-PAGO — Seed de datos demo para video (idempotente)
--
-- Uso:  docker exec -i dimed-pago-postgres psql -U dimed -d dimed_pago \
--         < scripts/seed-demo-video.sql
--
-- - Solo INSERTa (ON CONFLICT DO NOTHING / WHERE NOT EXISTS); no borra nada.
-- - Config: solo rellena valores vacíos o el placeholder "Mi Empresa".
-- - No crea comprobantes SRI (esto es un registro interno de cobros/pagos).
-- - Usuario demo: admin / admin123 (rol admin; el super_admin existente no
--   se toca — el trigger lo protege de todos modos).
-- ============================================================================
BEGIN;

-- ---------------------------------------------------------------------------
-- 1) Usuarios demo (admin + un cobrador). Password de ambos: admin123
-- ---------------------------------------------------------------------------
INSERT INTO pago_users (id, username, email, password_hash, full_name, role, is_active)
VALUES
  ('ad000000-0000-4000-8000-000000000001', 'admin',
   'admin@dimedhealthcare.com',
   '$2b$12$BUorTwKI5JmzJpIVsSA2ueqgTd34ZRvRpWZjblknYtd7g4h7nUDpG',
   'Administrador Demo', 'admin', TRUE),
  ('ad000000-0000-4000-8000-000000000002', 'mrodriguez',
   'mrodriguez@dimedhealthcare.com',
   '$2b$12$BUorTwKI5JmzJpIVsSA2ueqgTd34ZRvRpWZjblknYtd7g4h7nUDpG',
   'María Rodríguez Espinoza', 'cobrador', TRUE)
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2) Configuración de empresa (solo si está vacía o con placeholder)
-- ---------------------------------------------------------------------------
UPDATE pago_config SET value = 'DIMED HEALTHCARE S.A.', updated_at = NOW()
 WHERE key = 'company_name' AND (value IS NULL OR value = '' OR value = 'Mi Empresa');
UPDATE pago_config SET value = '1793193550001', updated_at = NOW()
 WHERE key = 'company_ruc' AND (value IS NULL OR value = '');
UPDATE pago_config SET value = 'Av. República de El Salvador N34-183 y Suiza, Quito — Ecuador', updated_at = NOW()
 WHERE key = 'company_address' AND (value IS NULL OR value = '');
UPDATE pago_config SET value = '02 382 6400', updated_at = NOW()
 WHERE key = 'company_phone' AND (value IS NULL OR value = '');
UPDATE pago_config SET value = 'cobros@dimedhealthcare.com', updated_at = NOW()
 WHERE key = 'company_email' AND (value IS NULL OR value = '');

-- ---------------------------------------------------------------------------
-- 3) Cuentas bancarias de la empresa (para el checkout por transferencia)
-- ---------------------------------------------------------------------------
INSERT INTO pago_bank_accounts (bank_name, account_type, account_number, holder_name, holder_doc, extra_instructions, display_order)
SELECT 'Banco Guayaquil', 'corriente', '0018903245', 'DIMED HEALTHCARE S.A.', '1793193550001',
       'Enviar comprobante indicando el código del cobro (COB-XXXXXX)', 1
WHERE NOT EXISTS (SELECT 1 FROM pago_bank_accounts WHERE account_number = '0018903245');

INSERT INTO pago_bank_accounts (bank_name, account_type, account_number, holder_name, holder_doc, display_order)
SELECT 'Produbanco', 'ahorros', '12058764310', 'DIMED HEALTHCARE S.A.', '1793193550001', 2
WHERE NOT EXISTS (SELECT 1 FROM pago_bank_accounts WHERE account_number = '12058764310');

-- ---------------------------------------------------------------------------
-- 4) Clientes (empresas con RUC de 13 dígitos ...001 y personas con cédula)
-- ---------------------------------------------------------------------------
INSERT INTO pago_customers (id, doc_type, doc_number, name, email, phone, country, address, created_by)
VALUES
  ('d3300000-0000-4000-8000-000000000001', 'ruc', '1791234567001', 'Clínica Metropolitana de Quito Cía. Ltda.',
   'pagos@clinicametropolitana.ec', '02 2456 789', 'EC', 'Av. Mariana de Jesús Oe7-02, Quito',
   'ad000000-0000-4000-8000-000000000001'),
  ('d3300000-0000-4000-8000-000000000002', 'ruc', '0991234567001', 'Centro Médico San Gabriel S.A.',
   'contabilidad@cmsangabriel.ec', '04 2687 145', 'EC', 'Cdla. Kennedy Norte, Av. Fco. de Orellana, Guayaquil',
   'ad000000-0000-4000-8000-000000000001'),
  ('d3300000-0000-4000-8000-000000000003', 'ruc', '1792345678001', 'Hospital del Valle HOSVALLE S.A.',
   'tesoreria@hosvalle.ec', '02 3958 200', 'EC', 'Av. Interoceánica km 12.5, Cumbayá — Quito',
   'ad000000-0000-4000-8000-000000000001'),
  ('d3300000-0000-4000-8000-000000000004', 'ruc', '0190123456001', 'Laboratorio Clínico Andes Cía. Ltda.',
   'admin@labandes.ec', '07 2831 460', 'EC', 'Av. Remigio Crespo 3-45, Cuenca',
   'ad000000-0000-4000-8000-000000000001'),
  ('d3300000-0000-4000-8000-000000000005', 'cedula', '1712345678', 'María Fernanda Torres Vaca',
   'mftorres@gmail.com', '099 845 2317', 'EC', 'La Carolina, Quito',
   'ad000000-0000-4000-8000-000000000001'),
  ('d3300000-0000-4000-8000-000000000006', 'cedula', '0923456789', 'Carlos Andrés Jaramillo Peña',
   'cjaramillo@hotmail.com', '098 512 7743', 'EC', 'Urdesa Central, Guayaquil',
   'ad000000-0000-4000-8000-000000000001'),
  ('d3300000-0000-4000-8000-000000000007', 'cedula', '0104567890', 'Dra. Verónica Salazar Mogrovejo',
   'vsalazar.md@gmail.com', '098 761 0254', 'EC', 'Puertas del Sol, Cuenca',
   'ad000000-0000-4000-8000-000000000001'),
  ('d3300000-0000-4000-8000-000000000008', 'ruc', '1803456789001', 'Consultorio Odontológico Sonrisa Total',
   'sonrisatotal@outlook.com', '03 2421 890', 'EC', 'Av. Cevallos 15-40 y Mera, Ambato',
   'ad000000-0000-4000-8000-000000000001'),
  ('d3300000-0000-4000-8000-000000000009', 'cedula', '1305678901', 'Juan Pablo Cevallos Zambrano',
   'jpcevallos@yahoo.com', '099 330 8861', 'EC', 'Av. Flavio Reyes, Manta',
   'ad000000-0000-4000-8000-000000000001'),
  ('d3300000-0000-4000-8000-000000000010', 'ruc', '1794567890001', 'Centro de Imagen Diagnóstica RX Norte S.A.',
   'facturas@rxnorte.ec', '02 2244 613', 'EC', 'Av. El Inca E5-30, Quito',
   'ad000000-0000-4000-8000-000000000001'),
  ('d3300000-0000-4000-8000-000000000011', 'cedula', '0605432109', 'Rosa Elena Paredes Guamán',
   'rosaparedes61@gmail.com', '098 224 9106', 'EC', 'Barrio La Estación, Riobamba',
   'ad000000-0000-4000-8000-000000000001'),
  ('d3300000-0000-4000-8000-000000000012', 'ruc', '0992345678001', 'Fisioterapia Integral Kines S.A.',
   'kines.pagos@gmail.com', '04 2390 577', 'EC', 'Av. Víctor Emilio Estrada 626, Guayaquil',
   'ad000000-0000-4000-8000-000000000001')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 5) Cobros
--    Estados: pagado (6), pendiente (4: 2 vigentes + 2 vencidos),
--             en_revision (2), anulado (1), reembolsado (1)
-- ---------------------------------------------------------------------------
INSERT INTO pago_charges (id, customer_id, concept, description, amount, due_date, status,
                          link_token, link_expires_at, allowed_methods, created_by, created_at, updated_at)
VALUES
  -- ---- PAGADOS ----
  ('c4400000-0000-4000-8000-000000000001', 'd3300000-0000-4000-8000-000000000001',
   'Mantenimiento anual ecógrafo GE Logiq P9', 'Contrato MANT-2026-014, incluye 2 visitas técnicas',
   1850.00, NULL, 'pagado', 'demo-tk-a1b2c3d4e5f60718293a4b5c6d7e8f01', NOW() + INTERVAL '60 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000001', NOW() - INTERVAL '16 days', NOW() - INTERVAL '15 days'),
  ('c4400000-0000-4000-8000-000000000002', 'd3300000-0000-4000-8000-000000000003',
   'Monitor multiparámetro Mindray — cuota 2/6', 'Plan de financiamiento directo, contrato FIN-2026-031',
   745.50, NULL, 'pagado', 'demo-tk-b2c3d4e5f60718293a4b5c6d7e8f0a12', NOW() + INTERVAL '60 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000001', NOW() - INTERVAL '12 days', NOW() - INTERVAL '11 days'),
  ('c4400000-0000-4000-8000-000000000003', 'd3300000-0000-4000-8000-000000000004',
   'Insumos de laboratorio — pedido #4512', 'Reactivos de química sanguínea y tubos EDTA',
   428.90, NULL, 'pagado', 'demo-tk-c3d4e5f60718293a4b5c6d7e8f0a1b23', NOW() + INTERVAL '60 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000002', NOW() - INTERVAL '9 days', NOW() - INTERVAL '8 days'),
  ('c4400000-0000-4000-8000-000000000004', 'd3300000-0000-4000-8000-000000000007',
   'Electrodos y papel térmico ECG', 'Caja x 500 electrodos + 10 rollos papel 80 mm',
   186.20, NULL, 'pagado', 'demo-tk-d4e5f60718293a4b5c6d7e8f0a1b2c34', NOW() + INTERVAL '60 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000002', NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days'),
  ('c4400000-0000-4000-8000-000000000005', 'd3300000-0000-4000-8000-000000000008',
   'Compresor odontológico — saldo final', 'Saldo 50% instalación incluida, orden OC-2026-088',
   612.00, NULL, 'pagado', 'demo-tk-e5f60718293a4b5c6d7e8f0a1b2c3d45', NOW() + INTERVAL '60 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000001', NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days'),
  ('c4400000-0000-4000-8000-000000000006', 'd3300000-0000-4000-8000-000000000011',
   'Tensiómetro digital + glucómetro', 'Kit domiciliario con estuche',
   94.50, NULL, 'pagado', 'demo-tk-f60718293a4b5c6d7e8f0a1b2c3d4e56', NOW() + INTERVAL '60 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000002', NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),
  -- ---- PENDIENTES vigentes ----
  ('c4400000-0000-4000-8000-000000000007', 'd3300000-0000-4000-8000-000000000002',
   'Ecógrafo portátil SonoSite — anticipo 50%', 'Anticipo para importación, proforma PRO-2026-112',
   4250.00, CURRENT_DATE + 12, 'pendiente', 'demo-tk-0718293a4b5c6d7e8f0a1b2c3d4e5f67', NOW() + INTERVAL '60 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000001', NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days'),
  ('c4400000-0000-4000-8000-000000000008', 'd3300000-0000-4000-8000-000000000010',
   'Soporte técnico trimestral Q3-2026', 'Equipos de rayos X sala 1 y 2',
   980.00, CURRENT_DATE + 20, 'pendiente', 'demo-tk-18293a4b5c6d7e8f0a1b2c3d4e5f6078', NOW() + INTERVAL '60 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000001', NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),
  -- ---- PENDIENTES vencidos (alimentan el contador "vencidos" del dashboard) ----
  ('c4400000-0000-4000-8000-000000000009', 'd3300000-0000-4000-8000-000000000006',
   'Silla de ruedas eléctrica — cuota 3/4', 'Plan familiar, convenio CV-2026-007',
   385.00, CURRENT_DATE - 6, 'pendiente', 'demo-tk-293a4b5c6d7e8f0a1b2c3d4e5f607189', NOW() + INTERVAL '45 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000002', NOW() - INTERVAL '26 days', NOW() - INTERVAL '26 days'),
  ('c4400000-0000-4000-8000-000000000010', 'd3300000-0000-4000-8000-000000000012',
   'Camilla eléctrica de fisioterapia', 'Modelo 3 cuerpos, garantía 2 años',
   1290.00, CURRENT_DATE - 2, 'pendiente', 'demo-tk-3a4b5c6d7e8f0a1b2c3d4e5f6071829a', NOW() + INTERVAL '45 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000001', NOW() - INTERVAL '20 days', NOW() - INTERVAL '20 days'),
  -- ---- EN REVISIÓN (transferencias por conciliar) ----
  ('c4400000-0000-4000-8000-000000000011', 'd3300000-0000-4000-8000-000000000005',
   'Nebulizador ultrasónico portátil', 'Incluye kit de mascarillas adulto/pediátrica',
   148.75, CURRENT_DATE + 5, 'en_revision', 'demo-tk-4b5c6d7e8f0a1b2c3d4e5f6071829a3b', NOW() + INTERVAL '45 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000002', NOW() - INTERVAL '4 days', NOW() - INTERVAL '6 hours'),
  ('c4400000-0000-4000-8000-000000000012', 'd3300000-0000-4000-8000-000000000003',
   'Desfibrilador bifásico — anticipo', 'Anticipo 30%, proforma PRO-2026-127',
   2170.00, CURRENT_DATE + 8, 'en_revision', 'demo-tk-5c6d7e8f0a1b2c3d4e5f6071829a3b4c', NOW() + INTERVAL '45 days',
   '{transferencia}', 'ad000000-0000-4000-8000-000000000001', NOW() - INTERVAL '2 days', NOW() - INTERVAL '3 hours'),
  -- ---- ANULADO ----
  ('c4400000-0000-4000-8000-000000000013', 'd3300000-0000-4000-8000-000000000009',
   'Oxímetro de pulso profesional', 'Pedido duplicado por error',
   75.00, NULL, 'anulado', 'demo-tk-6d7e8f0a1b2c3d4e5f6071829a3b4c5d', NOW() + INTERVAL '45 days',
   '{tarjeta,transferencia}', 'ad000000-0000-4000-8000-000000000002', NOW() - INTERVAL '14 days', NOW() - INTERVAL '13 days'),
  -- ---- REEMBOLSADO ----
  ('c4400000-0000-4000-8000-000000000014', 'd3300000-0000-4000-8000-000000000002',
   'Lámpara cielítica LED — reserva', 'Cliente cambió de modelo; se reembolsó la reserva',
   500.00, NULL, 'reembolsado', 'demo-tk-7e8f0a1b2c3d4e5f6071829a3b4c5d6e', NOW() + INTERVAL '45 days',
   '{tarjeta}', 'ad000000-0000-4000-8000-000000000001', NOW() - INTERVAL '22 days', NOW() - INTERVAL '10 days')
ON CONFLICT DO NOTHING;

-- El cobro anulado lleva quién/cuándo/por qué (solo si aún no lo tiene)
UPDATE pago_charges
   SET anulado_by = 'ad000000-0000-4000-8000-000000000001',
       anulado_at = NOW() - INTERVAL '13 days',
       anulado_reason = 'Pedido duplicado — se mantiene COB del pedido original'
 WHERE id = 'c4400000-0000-4000-8000-000000000013' AND anulado_at IS NULL;

-- ---------------------------------------------------------------------------
-- 6) Pagos
--    Métodos variados: tarjeta (aprobada/rechazada/reembolsada),
--    transferencia (aprobada/en revisión), efectivo y cheque.
--    receipt_number sale de la secuencia real para no chocar con recibos futuros.
-- ---------------------------------------------------------------------------
INSERT INTO pago_payments (id, charge_id, method, amount, currency, status, gateway, gateway_ref,
                           gateway_status, card_brand, card_last4, payer_name, payer_email, payer_ip,
                           receipt_number, review_note, reviewed_by, reviewed_at, created_by,
                           error_message, refund_ref, refunded_by, refunded_at, created_at, updated_at)
VALUES
  -- tarjeta aprobada (COB-1)
  ('e5500000-0000-4000-8000-000000000001', 'c4400000-0000-4000-8000-000000000001',
   'tarjeta', 1850.00, 'USD', 'aprobado', 'sandbox', 'sbx_ch_9f2a71c3', 'approved', 'visa', '4242',
   'Gabriela Núñez — Tesorería CMQ', 'pagos@clinicametropolitana.ec', '181.39.24.101',
   'REC-' || to_char(nextval('pago_receipt_seq'), 'FM000000'), NULL, NULL, NULL, NULL,
   NULL, NULL, NULL, NULL, NOW() - INTERVAL '15 days', NOW() - INTERVAL '15 days'),
  -- transferencia aprobada tras conciliación (COB-2)
  ('e5500000-0000-4000-8000-000000000002', 'c4400000-0000-4000-8000-000000000002',
   'transferencia', 745.50, 'USD', 'aprobado', NULL, NULL, NULL, NULL, NULL,
   'Depto. Financiero HOSVALLE', 'tesoreria@hosvalle.ec', '190.152.66.4',
   'REC-' || to_char(nextval('pago_receipt_seq'), 'FM000000'),
   'Verificada contra estado de cuenta Banco Pichincha 11-jul',
   'ad000000-0000-4000-8000-000000000001', NOW() - INTERVAL '11 days', NULL,
   NULL, NULL, NULL, NULL, NOW() - INTERVAL '12 days', NOW() - INTERVAL '11 days'),
  -- efectivo en ventanilla (COB-3)
  ('e5500000-0000-4000-8000-000000000003', 'c4400000-0000-4000-8000-000000000003',
   'efectivo', 428.90, 'USD', 'aprobado', NULL, NULL, NULL, NULL, NULL,
   NULL, NULL, NULL,
   'REC-' || to_char(nextval('pago_receipt_seq'), 'FM000000'),
   'Pago en oficina Quito — caja principal', NULL, NULL,
   'ad000000-0000-4000-8000-000000000002',
   NULL, NULL, NULL, NULL, NOW() - INTERVAL '8 days', NOW() - INTERVAL '8 days'),
  -- tarjeta aprobada (COB-4)
  ('e5500000-0000-4000-8000-000000000004', 'c4400000-0000-4000-8000-000000000004',
   'tarjeta', 186.20, 'USD', 'aprobado', 'sandbox', 'sbx_ch_5d18e0ab', 'approved', 'mastercard', '5510',
   'Verónica Salazar', 'vsalazar.md@gmail.com', '186.4.152.77',
   'REC-' || to_char(nextval('pago_receipt_seq'), 'FM000000'), NULL, NULL, NULL, NULL,
   NULL, NULL, NULL, NULL, NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days'),
  -- cheque en ventanilla (COB-5)
  ('e5500000-0000-4000-8000-000000000005', 'c4400000-0000-4000-8000-000000000005',
   'cheque', 612.00, 'USD', 'aprobado', NULL, NULL, NULL, NULL, NULL,
   NULL, NULL, NULL,
   'REC-' || to_char(nextval('pago_receipt_seq'), 'FM000000'),
   'Cheque Banco del Austro #001245 — efectivizado', NULL, NULL,
   'ad000000-0000-4000-8000-000000000001',
   NULL, NULL, NULL, NULL, NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days'),
  -- transferencia aprobada (COB-6)
  ('e5500000-0000-4000-8000-000000000006', 'c4400000-0000-4000-8000-000000000006',
   'transferencia', 94.50, 'USD', 'aprobado', NULL, NULL, NULL, NULL, NULL,
   'Rosa Paredes', 'rosaparedes61@gmail.com', '157.100.43.12',
   'REC-' || to_char(nextval('pago_receipt_seq'), 'FM000000'),
   'Verificada en Banco Guayaquil — 17-jul',
   'ad000000-0000-4000-8000-000000000001', NOW() - INTERVAL '20 hours', NULL,
   NULL, NULL, NULL, NULL, NOW() - INTERVAL '1 day', NOW() - INTERVAL '20 hours'),
  -- intento de tarjeta RECHAZADO sobre cobro aún pendiente (COB-7)
  ('e5500000-0000-4000-8000-000000000007', 'c4400000-0000-4000-8000-000000000007',
   'tarjeta', 4250.00, 'USD', 'rechazado', 'sandbox', 'sbx_ch_c77b2e19', 'insufficient_funds', 'visa', '9021',
   'Contabilidad CMSG', 'contabilidad@cmsangabriel.ec', '186.101.9.230',
   NULL, NULL, NULL, NULL, NULL,
   'Fondos insuficientes', NULL, NULL, NULL, NOW() - INTERVAL '30 hours', NOW() - INTERVAL '30 hours'),
  -- transferencia EN REVISIÓN (COB-11) — aparece en Conciliación
  ('e5500000-0000-4000-8000-000000000008', 'c4400000-0000-4000-8000-000000000011',
   'transferencia', 148.75, 'USD', 'en_revision', NULL, NULL, NULL, NULL, NULL,
   'María Fernanda Torres', 'mftorres@gmail.com', '181.198.55.40',
   NULL, NULL, NULL, NULL, NULL,
   NULL, NULL, NULL, NULL, NOW() - INTERVAL '6 hours', NOW() - INTERVAL '6 hours'),
  -- transferencia EN REVISIÓN (COB-12) — aparece en Conciliación
  ('e5500000-0000-4000-8000-000000000009', 'c4400000-0000-4000-8000-000000000012',
   'transferencia', 2170.00, 'USD', 'en_revision', NULL, NULL, NULL, NULL, NULL,
   'HOSVALLE — Pagos a proveedores', 'tesoreria@hosvalle.ec', '190.152.66.4',
   NULL, NULL, NULL, NULL, NULL,
   NULL, NULL, NULL, NULL, NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours'),
  -- tarjeta REEMBOLSADA (COB-14)
  ('e5500000-0000-4000-8000-000000000010', 'c4400000-0000-4000-8000-000000000014',
   'tarjeta', 500.00, 'USD', 'reembolsado', 'sandbox', 'sbx_ch_31f8d4e6', 'refunded', 'visa', '7734',
   'Centro Médico San Gabriel', 'contabilidad@cmsangabriel.ec', '186.101.9.230',
   'REC-' || to_char(nextval('pago_receipt_seq'), 'FM000000'), NULL, NULL, NULL, NULL,
   NULL, 'sbx_rf_8a02c5d1', 'ad000000-0000-4000-8000-000000000001', NOW() - INTERVAL '10 days',
   NOW() - INTERVAL '21 days', NOW() - INTERVAL '10 days')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 7) Comprobantes de transferencia (PDFs; los archivos los crea
--    scripts/seed-demo-files.py dentro del contenedor)
-- ---------------------------------------------------------------------------
INSERT INTO pago_transfer_receipts (id, payment_id, file_path, original_filename, mime_type,
                                    size_bytes, reference, bank_name, transfer_date, uploaded_ip, uploaded_at)
VALUES
  ('f6600000-0000-4000-8000-000000000001', 'e5500000-0000-4000-8000-000000000002',
   'comprobantes/demo-transfer-01.pdf', 'comprobante-hosvalle.pdf', 'application/pdf', 2048,
   'TRX-2094817', 'Banco Pichincha', CURRENT_DATE - 12, '190.152.66.4', NOW() - INTERVAL '12 days'),
  ('f6600000-0000-4000-8000-000000000002', 'e5500000-0000-4000-8000-000000000006',
   'comprobantes/demo-transfer-02.pdf', 'transferencia_rosa.pdf', 'application/pdf', 2048,
   'BG-77120453', 'Banco Guayaquil', CURRENT_DATE - 1, '157.100.43.12', NOW() - INTERVAL '1 day'),
  ('f6600000-0000-4000-8000-000000000003', 'e5500000-0000-4000-8000-000000000008',
   'comprobantes/demo-transfer-03.pdf', 'comprobante_transferencia.pdf', 'application/pdf', 2048,
   'PICH-5563021', 'Banco Pichincha', CURRENT_DATE, '181.198.55.40', NOW() - INTERVAL '6 hours'),
  ('f6600000-0000-4000-8000-000000000004', 'e5500000-0000-4000-8000-000000000009',
   'comprobantes/demo-transfer-04.pdf', 'pago_desfibrilador_anticipo.pdf', 'application/pdf', 2048,
   'PROD-1187264', 'Produbanco', CURRENT_DATE, '190.152.66.4', NOW() - INTERVAL '3 hours')
ON CONFLICT DO NOTHING;

COMMIT;

-- Resumen
SELECT 'usuarios'  AS tabla, COUNT(*) FROM pago_users
UNION ALL SELECT 'clientes', COUNT(*) FROM pago_customers
UNION ALL SELECT 'cuentas_bancarias', COUNT(*) FROM pago_bank_accounts
UNION ALL SELECT 'cobros', COUNT(*) FROM pago_charges
UNION ALL SELECT 'pagos', COUNT(*) FROM pago_payments
UNION ALL SELECT 'comprobantes', COUNT(*) FROM pago_transfer_receipts;

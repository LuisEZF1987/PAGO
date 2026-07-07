-- Gateways con flujo de orden/captura (PayPal): el reembolso requiere el id de
-- CAPTURA, distinto del id de orden que vive en gateway_ref.
ALTER TABLE pago_payments ADD COLUMN IF NOT EXISTS gateway_capture_ref TEXT;

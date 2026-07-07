-- Pagos (intentos y exitosos) sobre un cobro + comprobantes de transferencia +
-- eventos de gateway (webhooks, con idempotencia).
-- PCI-DSS: JAMAS se guarda PAN/CVV; solo referencia externa + marca + ultimos 4.
CREATE SEQUENCE IF NOT EXISTS pago_receipt_seq;

CREATE TABLE IF NOT EXISTS pago_payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  charge_id UUID NOT NULL REFERENCES pago_charges(id),
  method TEXT NOT NULL CHECK (method IN ('tarjeta','transferencia','efectivo','cheque')),
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL
    CHECK (status IN ('iniciado','en_revision','aprobado','rechazado','reembolsado','anulado')),
  gateway TEXT,
  gateway_ref TEXT,
  gateway_status TEXT,
  card_brand TEXT,
  card_last4 TEXT,
  installments INT,
  payer_name TEXT,
  payer_email TEXT,
  payer_ip TEXT,
  receipt_number TEXT UNIQUE,
  error_message TEXT,
  created_by UUID REFERENCES pago_users(id) ON DELETE SET NULL,
  reviewed_by UUID REFERENCES pago_users(id) ON DELETE SET NULL,
  reviewed_at TIMESTAMPTZ,
  review_note TEXT,
  refund_ref TEXT,
  refunded_by UUID REFERENCES pago_users(id) ON DELETE SET NULL,
  refunded_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pago_payments_charge ON pago_payments(charge_id);
CREATE INDEX IF NOT EXISTS idx_pago_payments_status ON pago_payments(status);
CREATE INDEX IF NOT EXISTS idx_pago_payments_created ON pago_payments(created_at DESC);
-- v1: UN solo pago exitoso por cobro (sin abonos parciales). Quitar este indice
-- (y derivar 'pagado' de SUM(aprobados) >= amount) si algun dia se aceptan abonos.
CREATE UNIQUE INDEX IF NOT EXISTS uq_pago_payments_success
  ON pago_payments(charge_id) WHERE status IN ('aprobado','reembolsado');

CREATE TABLE IF NOT EXISTS pago_transfer_receipts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  payment_id UUID NOT NULL REFERENCES pago_payments(id),
  file_path TEXT NOT NULL,           -- relativo a /app/uploads; nombre aleatorio, NUNCA el original
  original_filename TEXT,
  mime_type TEXT,
  size_bytes INT,
  reference TEXT NOT NULL,           -- numero de referencia de la transferencia
  bank_name TEXT,
  transfer_date DATE,
  uploaded_ip TEXT,
  uploaded_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pago_transfer_receipts_payment ON pago_transfer_receipts(payment_id);

CREATE TABLE IF NOT EXISTS pago_gateway_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  payment_id UUID REFERENCES pago_payments(id),
  gateway TEXT NOT NULL,
  event_type TEXT,
  external_id TEXT NOT NULL,
  payload JSONB,
  received_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (gateway, external_id)
);

-- Cobros: lo que la empresa quiere cobrar. Cada cobro tiene UN enlace publico de pago
-- (link_token); regenerarlo invalida el anterior. 'vencido' NO es estado almacenado:
-- se deriva de due_date en las consultas (evita depender de un cron).
CREATE SEQUENCE IF NOT EXISTS pago_charge_code_seq;

CREATE TABLE IF NOT EXISTS pago_charges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code TEXT UNIQUE NOT NULL
    DEFAULT ('COB-' || to_char(nextval('pago_charge_code_seq'), 'FM000000')),
  customer_id UUID NOT NULL REFERENCES pago_customers(id),
  concept TEXT NOT NULL,
  description TEXT,
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  currency TEXT NOT NULL DEFAULT 'USD',
  due_date DATE,
  status TEXT NOT NULL DEFAULT 'pendiente'
    CHECK (status IN ('pendiente','en_revision','pagado','reembolsado','anulado')),
  link_token TEXT UNIQUE NOT NULL,
  link_expires_at TIMESTAMPTZ,
  allowed_methods TEXT[] NOT NULL DEFAULT '{tarjeta,transferencia}',
  created_by UUID REFERENCES pago_users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  anulado_by UUID REFERENCES pago_users(id) ON DELETE SET NULL,
  anulado_at TIMESTAMPTZ,
  anulado_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_pago_charges_status ON pago_charges(status);
CREATE INDEX IF NOT EXISTS idx_pago_charges_customer ON pago_charges(customer_id);
CREATE INDEX IF NOT EXISTS idx_pago_charges_created ON pago_charges(created_at DESC);

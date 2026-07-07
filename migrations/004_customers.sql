-- Clientes de la empresa (quienes pagan). Pueden ser de Ecuador o del exterior.
CREATE TABLE IF NOT EXISTS pago_customers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  doc_type TEXT NOT NULL DEFAULT 'cedula'
    CHECK (doc_type IN ('cedula','ruc','pasaporte','id_extranjera')),
  doc_number TEXT,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  country TEXT NOT NULL DEFAULT 'EC',
  address TEXT,
  notes TEXT,
  is_active BOOLEAN DEFAULT TRUE,
  created_by UUID REFERENCES pago_users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
-- Documento unico cuando se registra (permite clientes sin documento aun).
CREATE UNIQUE INDEX IF NOT EXISTS uq_pago_customers_doc
  ON pago_customers(doc_type, doc_number) WHERE doc_number IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pago_customers_name ON pago_customers(name);

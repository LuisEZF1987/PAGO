-- Cuentas bancarias de la empresa: se muestran al pagador en la opcion "transferencia".
-- swift_bic permite recibir transferencias del exterior.
CREATE TABLE IF NOT EXISTS pago_bank_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bank_name TEXT NOT NULL,
  account_type TEXT NOT NULL DEFAULT 'corriente'
    CHECK (account_type IN ('corriente','ahorros')),
  account_number TEXT NOT NULL,
  holder_name TEXT NOT NULL,
  holder_doc TEXT,
  swift_bic TEXT,
  extra_instructions TEXT,
  is_active BOOLEAN DEFAULT TRUE,
  display_order INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

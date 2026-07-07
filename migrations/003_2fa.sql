-- 2FA TOTP para usuarios. Idempotente.
-- El secreto se guarda CIFRADO (Fernet derivado del JWT_SECRET del stack).
ALTER TABLE pago_users ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE pago_users ADD COLUMN IF NOT EXISTS totp_pending_secret TEXT;
ALTER TABLE pago_users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE pago_users ADD COLUMN IF NOT EXISTS totp_last_counter BIGINT;

-- Codigos de recuperacion (un solo uso; se guarda el hash, nunca el codigo).
CREATE TABLE IF NOT EXISTS pago_2fa_recovery (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES pago_users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pago_2fa_recovery_user ON pago_2fa_recovery(user_id);

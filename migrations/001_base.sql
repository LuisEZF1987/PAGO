-- Dimed-PAGO: tablas base (config de empresa, usuarios, auditoria, login attempts)
-- DB destino: dimed_pago. Tablas con prefijo pago_.

CREATE TABLE IF NOT EXISTS pago_config (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO pago_config (key, value) VALUES
  ('company_name', 'Mi Empresa'),
  ('company_ruc', ''),
  ('company_address', ''),
  ('company_phone', ''),
  ('company_email', ''),
  ('currency', 'USD'),
  ('link_default_days', '90')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS pago_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('super_admin','admin','cobrador')),
  is_active BOOLEAN DEFAULT TRUE,
  is_protected BOOLEAN DEFAULT FALSE,
  last_login TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pago_users_username ON pago_users(username);
CREATE INDEX IF NOT EXISTS idx_pago_users_role ON pago_users(role);

CREATE TABLE IF NOT EXISTS pago_audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES pago_users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity TEXT,
  entity_id TEXT,
  details JSONB,
  ip_address TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pago_audit_user ON pago_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_pago_audit_entity ON pago_audit_log(entity, entity_id);
CREATE INDEX IF NOT EXISTS idx_pago_audit_created ON pago_audit_log(created_at DESC);

CREATE TABLE IF NOT EXISTS pago_login_attempts (
  id SERIAL PRIMARY KEY,
  username   TEXT,
  ip_address TEXT,
  success    BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pago_login_attempts_user ON pago_login_attempts (username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pago_login_attempts_ip   ON pago_login_attempts (ip_address, created_at DESC);

-- Proteccion del super administrador (a nivel de BD, a prueba de cualquier endpoint):
-- exactamente UNO; no se elimina ni modifica (salvo last_login); y NO se pueden
-- crear ni promover super_admins adicionales.
CREATE OR REPLACE FUNCTION protect_pago_superadmin() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.role = 'super_admin' THEN
      RAISE EXCEPTION 'El super administrador no puede ser eliminado';
    END IF;
    RETURN OLD;
  ELSIF TG_OP = 'UPDATE' THEN
    IF OLD.role = 'super_admin' THEN
      IF NEW.username <> OLD.username
         OR NEW.password_hash <> OLD.password_hash
         OR NEW.role <> OLD.role
         OR COALESCE(NEW.is_active, TRUE) <> COALESCE(OLD.is_active, TRUE) THEN
        RAISE EXCEPTION 'El super administrador no puede ser modificado';
      END IF;
      RETURN NEW;
    END IF;
    IF NEW.role = 'super_admin' THEN
      RAISE EXCEPTION 'No se puede promover a otro usuario a super administrador';
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'INSERT' THEN
    IF NEW.role = 'super_admin' AND EXISTS (SELECT 1 FROM pago_users WHERE role = 'super_admin') THEN
      RAISE EXCEPTION 'Ya existe un super administrador; no se puede crear otro';
    END IF;
    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_protect_pago_superadmin ON pago_users;
CREATE TRIGGER trg_protect_pago_superadmin
  BEFORE INSERT OR UPDATE OR DELETE ON pago_users
  FOR EACH ROW EXECUTE FUNCTION protect_pago_superadmin();

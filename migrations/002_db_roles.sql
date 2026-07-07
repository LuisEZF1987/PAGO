-- Migration 002: rol de aplicacion de menor privilegio (defensa en profundidad).
-- El servicio se conecta con 'dimed_app' (solo DML: SELECT/INSERT/UPDATE/DELETE);
-- el rol dueño 'dimed' queda SOLO para migraciones (contenedor init). Asi, un eventual
-- compromiso o inyeccion no puede DROP/ALTER/CREATE tablas.
-- La contrasena de dimed_app la fija run-migrations.sh desde APP_DB_PASSWORD (no se versiona).

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dimed_app') THEN
    CREATE ROLE dimed_app LOGIN;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO dimed_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dimed_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO dimed_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO dimed_app;

-- Objetos futuros (los crea 'dimed' en proximas migraciones): heredan los permisos.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO dimed_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO dimed_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO dimed_app;

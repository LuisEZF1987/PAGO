#!/bin/sh
set -e

echo "[migrations] Esperando postgres..."
until pg_isready -h postgres -U "$DB_USER" -d "$DB_NAME" -q; do sleep 1; done
echo "[migrations] Postgres listo."

psql -h postgres -U "$DB_USER" -d "$DB_NAME" -c "
  CREATE TABLE IF NOT EXISTS pago_migrations (
    id SERIAL PRIMARY KEY,
    filename TEXT UNIQUE NOT NULL,
    applied_at TIMESTAMPTZ DEFAULT NOW()
  );"

for f in /migrations/[0-9]*.sql; do
  fname=$(basename "$f")
  exists=$(psql -h postgres -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT COUNT(*) FROM pago_migrations WHERE filename='$fname'")
  if [ "$exists" = "0" ]; then
    echo "[migrations] Aplicando $fname ..."
    psql -h postgres -U "$DB_USER" -d "$DB_NAME" -f "$f"
    psql -h postgres -U "$DB_USER" -d "$DB_NAME" -c "INSERT INTO pago_migrations(filename) VALUES('$fname')"
    echo "[migrations] $fname OK"
  else
    echo "[migrations] $fname ya aplicada, skip"
  fi
done

# Rol de aplicacion de menor privilegio (002): fija su contrasena desde APP_DB_PASSWORD.
if [ -n "$APP_DB_PASSWORD" ]; then
  has_role=$(psql -h postgres -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT 1 FROM pg_roles WHERE rolname='dimed_app'")
  if [ "$has_role" = "1" ]; then
    echo "ALTER ROLE dimed_app PASSWORD :'pw'" | psql -h postgres -U "$DB_USER" -d "$DB_NAME" -v pw="$APP_DB_PASSWORD" -q
    echo "[migrations] contrasena de dimed_app fijada"
  fi
else
  echo "[migrations] WARN: APP_DB_PASSWORD vacia; dimed_app no podra conectar (los servicios fallaran)"
fi

echo "[migrations] Completado."

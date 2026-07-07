#!/usr/bin/env bash
set -euo pipefail

valida_pw() {  # politica: min 12 + al menos 3 de 4 clases
  local p="$1" n=0
  [ "${#p}" -ge 12 ] || { echo "  Error: la contrasena debe tener al menos 12 caracteres."; return 1; }
  case "$p" in *[a-z]*) n=$((n+1));; esac
  case "$p" in *[A-Z]*) n=$((n+1));; esac
  case "$p" in *[0-9]*) n=$((n+1));; esac
  case "$p" in *[!a-zA-Z0-9]*) n=$((n+1));; esac
  [ "$n" -ge 3 ] || { echo "  Error: combine 3 de: minusculas, mayusculas, numeros, simbolos."; return 1; }
  return 0
}

echo ""
echo "  Dimed-PAGO — Crear administrador"
echo "  ================================"
echo "  (si el stack aun no tiene super_admin lo crea como super_admin;"
echo "   si ya existe el super_admin protegido, crea un usuario rol 'admin')"
echo ""

read -rp "  Nombre completo: " FULL_NAME
read -rp "  Usuario:         " USERNAME
read -rp "  Email:           " EMAIL

while true; do
  read -rsp "  Contrasena:      " PASSWORD; echo
  if ! valida_pw "$PASSWORD"; then
    continue
  fi
  read -rsp "  Confirmar:       " PASSWORD2; echo
  [ "$PASSWORD" = "$PASSWORD2" ] && break
  echo "  Error: las contrasenas no coinciden."
done

echo ""
echo "  Creando usuario..."

# stdin (-i) es imprescindible para que el heredoc llegue a python dentro del
# contenedor; los datos van por -e (no interpolados en el codigo).
docker exec -i \
  -e NU_USERNAME="$USERNAME" -e NU_EMAIL="$EMAIL" \
  -e NU_FULL_NAME="$FULL_NAME" -e NU_PASSWORD="$PASSWORD" \
  "${PAGO_CONTAINER:-dimed-pago-core}" python3 - << 'PYEOF'
import bcrypt, psycopg2, os, sys

conn = psycopg2.connect(
    host=os.environ['DB_HOST'],
    port=os.environ.get('DB_PORT', 5432),
    dbname=os.environ.get('DB_NAME'),
    user=os.environ.get('DB_USER') or os.environ.get('PG_USER'),
    password=os.environ.get('DB_PASSWORD') or os.environ.get('PG_PASSWORD'),
)
cur = conn.cursor()
u, e, f, p = (os.environ['NU_USERNAME'], os.environ['NU_EMAIL'],
              os.environ['NU_FULL_NAME'], os.environ['NU_PASSWORD'])

cur.execute("SELECT id FROM pago_users WHERE username = %s", (u,))
if cur.fetchone():
    print(f"Error: el usuario '{u}' ya existe.")
    sys.exit(1)

# El trigger protect_pago_superadmin impide un segundo super_admin. Si ya hay
# uno, este usuario se crea con rol 'admin'.
cur.execute("SELECT 1 FROM pago_users WHERE role = 'super_admin'")
role = 'admin' if cur.fetchone() else 'super_admin'

pw_hash = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
cur.execute("""
    INSERT INTO pago_users (username, email, password_hash, full_name, role, is_active)
    VALUES (%s, %s, %s, %s, %s, TRUE)
""", (u, e, pw_hash, f, role))
conn.commit()
print(f"Usuario '{u}' creado correctamente con rol '{role}'.")
PYEOF

echo ""
echo "  Listo. Puede iniciar sesion en:"
echo "  http://localhost:${WEB_PORT:-9850}"
echo ""

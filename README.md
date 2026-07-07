# Dimed-PAGO

Aplicación de cobros para la empresa: **enlaces de pago** que se envían por
WhatsApp/email y que el cliente abre para pagar con **tarjeta** (pasarela
pluggable), **transferencia bancaria** (sube el comprobante y el staff lo
concilia) o registrando **efectivo/cheque** en ventanilla.

Producto standalone (no es parte de la suite clínica Dimed), con el mismo
stack: Flask + PostgreSQL 16 + Docker, JWT + 2FA TOTP, tema claro/oscuro.

## Cómo funciona

1. El staff crea un **cobro** (cliente, concepto, monto) → se genera un enlace
   público único (`/pay/<token>`, 256 bits de entropía, con vencimiento).
2. El cliente abre el enlace **sin login** y elige:
   - **Tarjeta** → se cobra a través del adaptador de pasarela activo.
   - **Transferencia** → ve las cuentas bancarias de la empresa, sube su
     comprobante (JPG/PNG/PDF) y queda **en revisión**.
3. El staff **concilia** las transferencias (aprobar/rechazar — solo admin) y
   registra pagos presenciales (efectivo/cheque).
4. Recibos en PDF, exportación a Excel, dashboard y auditoría completa.

## Pasarelas de tarjeta (arquitectura pluggable)

La pasarela activa se elige con la variable `GATEWAY` (`.env`). Incluidas:

- `sandbox` — **simulada**, para probar todo el flujo sin cuenta de comercio
  ni dinero real (resultados deterministas: aprobada / rechazada / fondos
  insuficientes / error de pasarela).
- `paypal` — **real** (Checkout/Orders API v2 + SDK JS de botones). Flujo
  orden→captura: el pagador aprueba en la ventana de PayPal (tarjeta o cuenta
  PayPal) y el servidor captura. Config: `PAYPAL_ENV` (live/sandbox),
  `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET` (crear una app REST en
  developer.paypal.com → Apps & Credentials). El dinero cae en el saldo
  PayPal Business y de ahí se retira al banco. Reembolsos integrados
  (usa `gateway_capture_ref`). Nota: si hay un proxy con CSP delante, debe
  permitir `*.paypal.com` y `*.paypalobjects.com` (script/connect/frame/img).

Para agregar otra (Kushki, Datafast, Nuvei, …):

1. Crear `pago/gateways/<nombre>.py` implementando el Protocol
   `PaymentGateway` de `pago/gateways/base.py`
   (`create_charge`, `confirm`, `refund`, `parse_webhook`).
2. Registrarla en `_REGISTRY` de `pago/gateways/__init__.py`.
3. `GATEWAY=<nombre>` en `.env`. Nada más cambia: la ruta de webhooks
   (`POST /api/webhooks/<gateway>`) ya existe y es idempotente.

### PCI-DSS (importante)

**Este servidor jamás recibe ni almacena PAN/CVV.** La tokenización de la
tarjeta ocurre en el navegador con el SDK del gateway; al backend solo llega
un token opaco y se persisten `gateway_ref`, `card_brand` y `card_last4`
(datos permitidos). En el checkout sandbox los campos de tarjeta son
decorativos y **no tienen atributo `name`**: nunca viajan al servidor.

Nota comercial: para cobrar tarjetas reales siempre hará falta una cuenta de
comercio con un procesador autorizado (en Ecuador: Kushki, Nuvei/Paymentez,
PlacetoPay, Datafast, PayPhone; internacional: PayPal). La app es tuya; el
movimiento del dinero lo hace el procesador y **liquida a tu cuenta bancaria**.

## Arranque rápido

```bash
cp .env.example .env      # completar PG_PASSWORD, APP_DB_PASSWORD, JWT_SECRET
docker compose up -d --build
./scripts/create_superadmin.sh
# http://localhost:9850
```

Flujo de prueba: crear cliente → crear cobro → "Copiar enlace" → abrirlo en
ventana incógnita → pagar con resultado "Aprobada" (sandbox) → descargar
recibo PDF → ver el pago en Dashboard/Pagos.

## Seguridad

- JWT HS256 con issuer/audience propios, cookie `httpOnly` + `SameSite=Strict`,
  refresh deslizante; 2FA TOTP con códigos de recuperación.
- Roles: `super_admin` (singleton protegido por trigger de BD), `admin`,
  `cobrador`. Quien cobra **no** aprueba sus propias transferencias.
- Rol de BD de mínimo privilegio (`dimed_app`, solo DML); el dueño `dimed`
  solo se usa en migraciones.
- Endpoints públicos con rate-limit por IP **y** límites de negocio contados
  en BD (5 intentos de tarjeta/15 min por cobro; 3 comprobantes/hora).
- Uploads validados por extensión **y** magic bytes, guardados con nombre
  aleatorio fuera del árbol servible y descargados solo con sesión.
- CSRF: el panel usa cookie `SameSite=Strict`; el checkout público no tiene
  sesión (el token del URL actúa como capability) y está limitado por rate-limits.
- Auditoría de todas las acciones y enmascaramiento de PII en logs.

## Desarrollo

```bash
pip install -r requirements-dev.txt
pytest -q            # unit; los tests @db se omiten sin PostgreSQL
ruff check .
```

Migraciones: SQL numerado en `migrations/` (las aplica el contenedor `init`).
CI: ruff + bandit + pip-audit + gitleaks + pytest contra Postgres real.

## Estados

```
COBRO: pendiente → pagado | en_revision | anulado
       en_revision → pagado | pendiente (rechazo) | anulado
       pagado → reembolsado
PAGO:  tarjeta: iniciado → aprobado | rechazado ; aprobado → reembolsado
       transferencia: en_revision → aprobado | rechazado
       efectivo/cheque: nace aprobado ; → anulado | reembolsado (manual)
```

"Vencido" se deriva de `due_date` (no es estado almacenado). v1 no maneja
abonos parciales (un pago exitoso por cobro, garantizado por índice único);
el esquema ya lo permite a futuro sin migración destructiva.

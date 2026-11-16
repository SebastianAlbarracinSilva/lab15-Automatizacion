# Informe de reconocimiento: example.com

- Modo: **domain** (reconocimiento activo: envia paquetes al objetivo)
- Inicio: 2026-11-16T17:21:51 | Fin: 2026-11-16T17:21:52

## Resumen

| Etapa | Estado | Hallazgo principal |
|---|---|---|
| whois | partial | registrar: RESERVED-Internet Assigned Numbers Authority; expira: 2027-08-13T04:00:00Z |
| dig | ok | A: 2, MX: 1, NS: 2, TXT: 2 |
| curl | ok | HTTP/2 200; faltan: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options |

## Registros DNS

| Tipo | Valor |
|---|---|
| A | 172.66.147.243 |
| A | 104.20.23.154 |
| MX | 0 . |
| NS | hera.ns.cloudflare.com. |
| NS | elliott.ns.cloudflare.com. |
| TXT | "v=spf1 -all" |
| TXT | "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9" |

## WHOIS

| Campo | Valor |
|---|---|
| registrar | RESERVED-Internet Assigned Numbers Authority |
| registration_date | 1995-08-14T04:00:00Z |
| expiry_date | 2027-08-13T04:00:00Z |
| registrant_organization | (no encontrado) |

## Cabeceras HTTP (https://example.com)

Respuesta: `HTTP/2 200`

| Cabecera | Valor |
|---|---|
| server | cloudflare |
| x-powered-by | (ausente) |
| content-security-policy | (ausente) |
| strict-transport-security | (ausente) |
| x-frame-options | (ausente) |

### Cabeceras de seguridad ausentes

- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options

Divulgacion de software: server presente(s); revisar si exponen version.

## Etapas con error o incompletas

- **whois**: datos parciales

# Informe de reconocimiento: 192.168.216.128

- Modo: **ip** (reconocimiento activo: envia paquetes al objetivo)
- Inicio: 2026-11-16T17:21:46 | Fin: 2026-11-16T17:21:51

## Resumen

| Etapa | Estado | Hallazgo principal |
|---|---|---|
| nmap | ok | 1 puertos abiertos: 22/ssh |
| dig | ok | sin registro PTR |
| whois | ok | Internet Assigned Numbers Authority (US) |

## Puertos abiertos

Escaneo: `nmap -sV --open --top-ports 100 -oX -`

| Host | Puerto | Servicio | Version |
|---|---:|---|---|
| 192.168.216.128 | 22 | ssh | OpenSSH 10.6p1 Debian 1 |

Nota: solo se probaron los puertos indicados; un puerto no listado no esta necesariamente cerrado.

## DNS inverso

Sin registro PTR.

## WHOIS

| Campo | Valor |
|---|---|
| organization | Internet Assigned Numbers Authority |
| country | US |
| network | 192.168.0.0 - 192.168.255.255 |

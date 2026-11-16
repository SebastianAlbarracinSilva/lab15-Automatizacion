# Informe de analisis de logs

Generado: 2026-11-16 17:15 | Archivos: `auth.log`, `access.log`

## Resumen de hallazgos

| Severidad | Categoria | Hallazgo |
|---|---|---|
| Critica | Acceso probable | Login exitoso de 91.240.118.7 como `root` (Mar 15 23:50:00) tras 27 fallos |
| Alta | Fuerza bruta SSH | 103.75.12.44: 48 fallos contra 4 usuarios |
| Alta | Fuerza bruta SSH | 91.240.118.7: 27 fallos contra 3 usuarios |
| Alta | Ataques web | 14 peticiones (command_injection: 2, path_traversal: 6, sqli: 4, xss: 4) desde 103.75.12.44, 91.240.118.7 |
| Media | Anomalia de trafico | 04:00 del 15/Mar/2025: 936 peticiones (z~4.61) |

## Autenticacion SSH (auth.log)

- Intentos fallidos: **161**
- Logins exitosos: **21**
- Proporcion fallidos:exitosos = **7.67:1**

### IPs con mas de 10 intentos fallidos

| IP | Fallos | Usuarios distintos |
|---|---:|---:|
| 103.75.12.44 | 48 | 4 |
| 91.240.118.7 | 27 | 3 |

### Usuarios objetivo

| Usuario | Intentos | La cuenta existe |
|---|---:|---|
| root | 54 | si |
| daniel | 20 | si |
| test | 19 | no (invalid user) |
| ubuntu | 14 | si |
| admin1 | 13 | no (invalid user) |
| admin | 10 | si |
| oracle | 9 | no (invalid user) |
| git | 9 | no (invalid user) |
| postgres | 7 | no (invalid user) |
| guest | 6 | no (invalid user) |

### Login exitoso despues de una racha de fallos (>= 5) - PRIORIDAD ALTA

| IP | Usuario | Hora | Metodo | Fallos previos |
|---|---|---|---|---:|
| 91.240.118.7 | root | Mar 15 23:50:00 | password | 27 |

## Trafico web (access.log)

- Lineas analizadas: **2680** (no reconocidas: 0)

### Peticiones sospechosas (14)

| Familia | Peticiones |
|---|---:|
| command_injection | 2 |
| path_traversal | 6 |
| sqli | 4 |
| xss | 4 |

| IP | Familia | Status | Hora | Ruta (tal como llego) |
|---|---|---|---|---|
| 103.75.12.44 | path_traversal | 200 | 15/Mar/2025:01:14:42 +0000 | `/admin/..%2f..%2f..%2fetc/passwd` |
| 103.75.12.44 | sqli | 403 | 15/Mar/2025:11:30:10 +0000 | `/item?id=1%20UN/**/ION%20SEL/**/ECT%20user,password%20FROM%20users--` |
| 103.75.12.44 | path_traversal, command_injection | 403 | 15/Mar/2025:15:39:44 +0000 | `/cgi-bin/test.cgi?cmd=id%3Bcat%20/etc/passwd` |
| 103.75.12.44 | sqli | 500 | 15/Mar/2025:17:50:18 +0000 | `/?id=1'%20UNION%20SELECT%201,2,3--` |
| 103.75.12.44 | path_traversal | 500 | 15/Mar/2025:22:51:24 +0000 | `/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd` |
| 103.75.12.44 | xss | 500 | 15/Mar/2025:23:05:19 +0000 | `/search?q=%3Cscript%3Ealert(1)%3C/script%3E` |
| 103.75.12.44 | xss | 500 | 15/Mar/2025:23:56:48 +0000 | `/search?q=%3Csvg%20onload%3Dalert(1)%3E` |
| 91.240.118.7 | path_traversal | 200 | 15/Mar/2025:01:54:56 +0000 | `/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd` |
| 91.240.118.7 | path_traversal, command_injection | 200 | 15/Mar/2025:03:57:17 +0000 | `/cgi-bin/test.cgi?cmd=id%3Bcat%20/etc/passwd` |
| 91.240.118.7 | xss | 500 | 15/Mar/2025:05:33:36 +0000 | `/search?q=%3Csvg%20onload%3Dalert(1)%3E` |
| 91.240.118.7 | path_traversal | 200 | 15/Mar/2025:06:45:38 +0000 | `/admin/..%2f..%2f..%2fetc/passwd` |
| 91.240.118.7 | sqli | 403 | 15/Mar/2025:09:01:39 +0000 | `/?id=1'%20UNION%20SELECT%201,2,3--` |
| 91.240.118.7 | sqli | 200 | 15/Mar/2025:12:48:51 +0000 | `/item?id=1%20UN/**/ION%20SEL/**/ECT%20user,password%20FROM%20users--` |
| 91.240.118.7 | xss | 200 | 15/Mar/2025:21:23:16 +0000 | `/search?q=%3Cscript%3Ealert(1)%3C/script%3E` |

Nota: una coincidencia es triaje, no veredicto; cada hit requiere revision o una segunda senal.

### Top 5 IPs por volumen

| IP | Peticiones |
|---|---:|
| 198.51.100.77 | 900 |
| 10.0.0.1 | 499 |
| 192.168.1.50 | 425 |
| 192.168.1.51 | 276 |
| 203.0.113.20 | 229 |

### Distribucion de codigos HTTP

| Status | Peticiones |
|---|---:|
| 200 | 2320 |
| 301 | 53 |
| 304 | 173 |
| 403 | 3 |
| 404 | 126 |
| 500 | 5 |

### Anomalias de trafico por hora (regla 3-sigma)

- Horas: 24, media: 111.7, desviacion: 178.7, umbral: 647.9 peticiones/hora (z maximo alcanzable con 24 muestras: 4.69)

    [ANOMALY] 04:00 (15/Mar/2025) - 936 requests (z~4.61σ, threshold=3.0σ)

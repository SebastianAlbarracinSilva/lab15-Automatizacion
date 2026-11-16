# Laboratorio 15: Automatizacion

Kit de reconocimiento y analisis de logs en Python: escaner de puertos concurrente, parser de nmap,
analizadores de logs con deteccion de anomalias y una herramienta de reconocimiento integrada con
audit log.

## Requisitos
- Kali Linux (VM en VMware), **Python 3.14.7** (se necesita 3.10 o superior).
- **Solo biblioteca estandar de Python: no hay dependencias de pip.**
- Herramientas del sistema: `nmap`, `ssh-keyscan`, `whois`, `dig`, `curl`, `git`
  (`sudo apt install nmap whois bind9-dnsutils openssh-client curl git`).
- Unico objetivo autorizado: `192.168.216.128` (ver `scope.txt`). El dominio de prueba es `example.com`
  (reservado para documentacion, RFC 2606).

## Scripts

| Script | Parte | Que hace | Ejemplo |
|---|---|---|---|
| `plant_logs.py` | 0 | Planta ataques en los logs base de Moodle y genera `planted.json` | `python3 plant_logs.py` |
| `scanner_seq.py` | 1A | Escaner secuencial de referencia (el de la guia) | `python3 scanner_seq.py` |
| `bench_threads.py` | 1A | Mide `ThreadPoolExecutor` con 50/200/500 workers | `python3 bench_threads.py` |
| `scanner.py` | 1B-D | Escaner con asyncio + Semaphore, CLI y salida JSON | `python3 scanner.py 192.168.216.128 --ports 1-1024 --rate 200 --output scan_rate200.json` |
| `parse_scan.py` | 2 | Parsea el XML de nmap y agrega el tipo de llave SSH | `python3 parse_scan.py --input scan.xml --output hosts.json` |
| `auth_analysis.py` | 3A | Fuerza bruta SSH, usuarios atacados, proporcion de fallos y login tras fallos | `python3 auth_analysis.py auth.log` |
| `log_analysis.py` | 3B-D | Ataques web, top 5 de IPs, codigos HTTP y anomalias 3-sigma | `python3 log_analysis.py access.log` |
| `make_report.py` | 3E | Combina 3A-3D en `report.md` | `python3 make_report.py --auth auth.log --access access.log` |
| `score_findings.py` | 3 | Compara `planted.json` con lo detectado y genera `findings_score.md` | `python3 score_findings.py` |
| `recon.py` | 4 | Reconocimiento de dominio o IP con `results.json`, `report.md` y `audit.log` | `python3 recon.py example.com --verbose` |

## Decisiones de diseno
- **Resultados clasificados, no colapsados (`scanner.py`).** Cada puerto queda como `open`, `closed`
  (llego RST), `filtered` (timeout) o `error:<errno>`. Un error nunca se reporta como "cerrado":
  a `--rate 2000` aparecieron 6 errores EMFILE (errno 24, limite `ulimit -n` = 1024), el JSON los lista
  y el programa termina con codigo 2 para que el resultado incompleto no pase como completo.
- **asyncio + Semaphore.** Limita las conexiones simultaneas sin crear hilos del sistema operativo;
  `--jitter` opcional rompe la regularidad del tiempo entre sondas.
- **Parseo de XML con `xml.etree`.** La direccion se elige por `addrtype` (no la primera `<address>`,
  que puede ser la MAC); `hostname` puede ser `null`; `ssh_host_key_type` es una lista porque el servidor
  presenta varias llaves (incluida `ssh-mldsa44-ed25519`, post-cuantica, de OpenSSH 10.6).
- **Regex robustas en los logs.** `invalid user` es opcional (el patron de la teoria perdia 63 fallos);
  las rutas se decodifican hasta 3 veces (doble codificacion), se quitan los comentarios SQL `/**/` y se
  pasa todo a minusculas; la ruta del log puede contener espacios; las horas sin trafico cuentan como 0
  para el 3-sigma.
- **`recon.py`.** Todas las llamadas externas pasan por `run_logged()` (audit log completo) y cada etapa
  corre dentro de `run_stage()`, que captura cualquier excepcion para que una etapa que falla no detenga
  a las demas. `results.json` guarda solo campos estructurados, sin texto crudo.
- **Privilegio minimo.** Ningun script necesita root: el escaner usa connect scan y nmap corre sin sudo.
  Solo los servidores de prueba de la Parte 0 usaron sudo, porque escuchan en puertos menores a 1024.

## Resultados principales
- Parte 1: los 4 puertos esperados (22, 210, 555, 888) se encontraron a todas las tasas; a rate 2000
  hubo 6 puertos sin resultado por EMFILE. Ver `notes/part1.md`.
- Parte 2: `nmap` sin `-p` no reporto el 210 (no esta entre los 1000 puertos por defecto); con
  `-p 1-1024` aparecieron los 4. Ver `notes/part2.md`.
- Parte 3: 12/12 elementos plantados detectados y 0 falsos positivos; los fallos del primer borrador y
  sus arreglos estan en `findings_score.md`. Ver `notes/part3.md`.
- Parte 4: ejecuciones en `sample_output/ip`, `sample_output/domain` y `sample_output/failure_test`
  (sin herramientas en el PATH, para mostrar que cada etapa falla de forma independiente).
  Ver `notes/part4.md`.

Las respuestas a las preguntas de cada parte estan en `notes/`.

## Quien hizo que
Laboratorio realizado **individualmente** por Sebastian Albarracin Silva, que cumplio los dos roles.

| Rol | Entregables |
|---|---|
| Ingeniero del escaner | `plant_logs.py`, `planted.json`, `scanner_seq.py`, `bench_threads.py`, `scanner.py`, `scan_rate200.json`, `scan_rate2000.json`, `parse_scan.py`, `hosts.json`, `findings_score.md` / `score_findings.py`, etapas de `recon.py` (whois, dig, curl, nmap) |
| Analista de logs | `scope.txt`, servidores de prueba (puertos 210/555/888 + SSH), `auth_analysis.py`, `log_analysis.py`, `make_report.py`, `report.md`, `run_logged()`/audit log, armado de `results.json` y `report.md` en `recon.py` |

Archivos de handoff: (1) `scope.txt`, (2) `auth.log` + `access.log` plantados, (3) `scan_rate200.json` +
`scan_rate2000.json`, (4) `report.md`, (5) `run_logged()`, (6) `results.json` de recon en modo IP.
Al trabajar solo, el analisis de logs se hizo sin consultar `planted.json` y la comparacion se hizo
despues con `score_findings.py`.

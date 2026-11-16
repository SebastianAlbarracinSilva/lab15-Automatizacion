#!/usr/bin/env python3
"""Parte 0: planta hallazgos en base-auth.log y base-access.log.

Genera auth.log, access.log y planted.json (respuesta esperada del analisis).
Ejecutar en la carpeta donde estan los logs base: python3 plant_logs.py
"""
import json
import random

# --- parametros elegidos por el ingeniero ---
ATTACKERS = {"103.75.12.44": 48, "91.240.118.7": 27}  # IP atacante -> intentos fallidos
INVALID_SHARE = 0.4            # proporcion de fallos contra cuentas inexistentes
BREACHED = "91.240.118.7"      # este atacante termina con un login exitoso
SPIKE_HOUR = 4                 # hora del pico de trafico (0-23)
SPIKE_SIZE = 900               # peticiones extra en esa hora
SPIKE_IP = "198.51.100.77"     # origen del pico

# (ruta, familia, custom)
ATTACKS = [
    ("/?id=1'%20UNION%20SELECT%201,2,3--", "sqli", False),
    ("/admin/..%2f..%2f..%2fetc/passwd", "path_traversal", False),
    ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "xss", False),
    ("/cgi-bin/test.cgi?cmd=id%3Bcat%20/etc/passwd", "command_injection", False),
    # Payloads propios: pensados para evadir el patron basico de la teoria
    ("/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "path_traversal", True),  # doble codificacion
    ("/item?id=1%20UN/**/ION%20SEL/**/ECT%20user,password%20FROM%20users--", "sqli", True),   # comentario SQL parte la palabra
    ("/search?q=%3Csvg%20onload%3Dalert(1)%3E", "xss", True),                                 # XSS sin <script
]
# --- fin de parametros ---


def stamp() -> str:
    return f"{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}"


def main() -> None:
    with open("base-auth.log", encoding="utf-8") as f:
        auth = f.read().splitlines()

    invalid_lines = 0
    for ip, n in ATTACKERS.items():
        for _ in range(n):
            if random.random() < INVALID_SHARE:
                who = f"invalid user {random.choice(['test', 'oracle', 'admin1'])}"
                invalid_lines += 1
            else:
                who = "root"
            auth.append(
                f"Mar 15 {stamp()} kali sshd[2200]: Failed password for {who} "
                f"from {ip} port {random.randint(40000, 60000)} ssh2"
            )
    auth.append(f"Mar 15 23:50:00 kali sshd[2201]: Accepted password for root from {BREACHED} port 51000 ssh2")

    with open("auth.log", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(auth)) + "\n")

    with open("base-access.log", encoding="utf-8") as f:
        web = f.read().splitlines()

    for _ in range(SPIKE_SIZE):
        t = f"{SPIKE_HOUR:02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}"
        web.append(f'{SPIKE_IP} - - [15/Mar/2025:{t} +0000] "GET / HTTP/1.1" 200 {random.randint(200, 5000)}')

    for path, _family, _custom in ATTACKS:
        for ip in ATTACKERS:
            web.append(
                f'{ip} - - [15/Mar/2025:{stamp()} +0000] "GET {path} HTTP/1.1" '
                f'{random.choice([200, 403, 500])} {random.randint(200, 900)}'
            )

    with open("access.log", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(web)) + "\n")

    planted = {
        "attacker_ips": ATTACKERS,
        "invalid_user_lines_added": invalid_lines,
        "successful_login_after_failures": BREACHED,
        "traffic_spike": {"hour": SPIKE_HOUR, "source_ip": SPIKE_IP, "extra_requests": SPIKE_SIZE},
        "attack_paths": [
            {"path": p, "family": fam, "custom": custom, "sent_by": list(ATTACKERS)}
            for p, fam, custom in ATTACKS
        ],
    }
    with open("planted.json", "w", encoding="utf-8") as f:
        json.dump(planted, f, indent=2)

    print(f"auth.log, access.log y planted.json generados ({invalid_lines} lineas 'invalid user').")


if __name__ == "__main__":
    main()

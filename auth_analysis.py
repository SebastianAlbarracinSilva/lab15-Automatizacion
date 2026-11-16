#!/usr/bin/env python3
"""Parte 3A: analisis de auth.log (fuerza bruta SSH).

Ejemplo:
  python3 auth_analysis.py auth.log
  python3 auth_analysis.py auth.log --threshold 10 --run 5 --json
"""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# "invalid user " es opcional: sin eso se pierden los intentos contra cuentas inexistentes
FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?sshd\[\d+\]: "
    r"(?:message repeated (?P<rep>\d+) times: \[ )?"
    r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F.:]+) port"
)
ACCEPTED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?sshd\[\d+\]: "
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+) port"
)


def analyze_auth(path: str, threshold: int = 10, run: int = 5) -> dict:
    fails_per_ip: Counter = Counter()
    users_per_ip: dict[str, set] = defaultdict(set)
    user_attempts: Counter = Counter()
    invalid_users: set = set()
    streak: Counter = Counter()          # fallos consecutivos por IP desde su ultimo exito
    breaches = []
    total_failed = total_ok = 0

    with Path(path).open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if m := FAILED.search(line):
                n = int(m.group("rep") or 1)
                ip, user = m.group("ip"), m.group("user")
                total_failed += n
                fails_per_ip[ip] += n
                users_per_ip[ip].add(user)
                user_attempts[user] += n
                if m.group("invalid"):
                    invalid_users.add(user)
                streak[ip] += n
            elif m := ACCEPTED.search(line):
                ip = m.group("ip")
                total_ok += 1
                if streak[ip] >= run:
                    breaches.append({
                        "ip": ip, "user": m.group("user"), "time": m.group("ts"),
                        "method": m.group("method"), "failures_before": streak[ip],
                    })
                streak[ip] = 0

    brute = [
        {"ip": ip, "failures": n, "distinct_users": len(users_per_ip[ip])}
        for ip, n in fails_per_ip.most_common() if n > threshold
    ]
    return {
        "total_failed": total_failed,
        "total_successful": total_ok,
        "failed_to_success_ratio": round(total_failed / total_ok, 2) if total_ok else None,
        "brute_force_ips": brute,
        "targeted_users": [
            {"user": u, "attempts": n, "account_exists": u not in invalid_users}
            for u, n in user_attempts.most_common()
        ],
        "success_after_failures": breaches,
        "params": {"threshold": threshold, "run": run},
    }


def to_markdown(r: dict) -> str:
    p = r["params"]
    ratio = r["failed_to_success_ratio"]
    out = ["## Autenticacion SSH (auth.log)", ""]
    out.append(f"- Intentos fallidos: **{r['total_failed']}**")
    out.append(f"- Logins exitosos: **{r['total_successful']}**")
    out.append(f"- Proporcion fallidos:exitosos = **{ratio if ratio is not None else 'n/a (0 exitos)'}:1**")
    out += ["", f"### IPs con mas de {p['threshold']} intentos fallidos", ""]
    if r["brute_force_ips"]:
        out += ["| IP | Fallos | Usuarios distintos |", "|---|---:|---:|"]
        out += [f"| {b['ip']} | {b['failures']} | {b['distinct_users']} |" for b in r["brute_force_ips"]]
    else:
        out.append("Ninguna.")
    out += ["", "### Usuarios objetivo", "", "| Usuario | Intentos | La cuenta existe |", "|---|---:|---|"]
    out += [f"| {u['user']} | {u['attempts']} | {'si' if u['account_exists'] else 'no (invalid user)'} |"
            for u in r["targeted_users"]]
    out += ["", f"### Login exitoso despues de una racha de fallos (>= {p['run']}) - PRIORIDAD ALTA", ""]
    if r["success_after_failures"]:
        out += ["| IP | Usuario | Hora | Metodo | Fallos previos |", "|---|---|---|---|---:|"]
        out += [f"| {b['ip']} | {b['user']} | {b['time']} | {b['method']} | {b['failures_before']} |"
                for b in r["success_after_failures"]]
    else:
        out.append("Ninguno.")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Detecta fuerza bruta SSH en auth.log.")
    ap.add_argument("logfile", help="Ruta a auth.log")
    ap.add_argument("--threshold", type=int, default=10, help="Fallos por IP para marcarla (estricto >, default 10)")
    ap.add_argument("--run", type=int, default=5, help="Fallos previos minimos para alertar un exito (default 5)")
    ap.add_argument("--json", action="store_true", help="Salida JSON en vez de Markdown")
    args = ap.parse_args()
    try:
        result = analyze_auth(args.logfile, args.threshold, args.run)
    except OSError as e:
        print(f"Error leyendo {args.logfile}: {e}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2) if args.json else to_markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())

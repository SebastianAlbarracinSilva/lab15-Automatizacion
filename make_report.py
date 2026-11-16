#!/usr/bin/env python3
"""Parte 3E: combina auth_analysis y log_analysis en report.md.

Ejemplo:
  python3 make_report.py --auth auth.log --access access.log --output report.md
"""
import argparse
import sys
from datetime import datetime

from auth_analysis import analyze_auth, to_markdown as auth_md
from log_analysis import analyze_web, to_markdown as web_md


def summary(a: dict, w: dict) -> str:
    rows = []
    for b in a["success_after_failures"]:
        rows.append(("Critica", "Acceso probable",
                     f"Login exitoso de {b['ip']} como `{b['user']}` ({b['time']}) tras {b['failures_before']} fallos"))
    for b in a["brute_force_ips"]:
        rows.append(("Alta", "Fuerza bruta SSH",
                     f"{b['ip']}: {b['failures']} fallos contra {b['distinct_users']} usuarios"))
    if w["suspicious_requests"]:
        ips = ", ".join(sorted({s["ip"] for s in w["suspicious_requests"]}))
        fams = ", ".join(f"{k}: {v}" for k, v in sorted(w["suspicious_by_family"].items()))
        rows.append(("Alta", "Ataques web",
                     f"{len(w['suspicious_requests'])} peticiones ({fams}) desde {ips}"))
    for an in w["anomalies"]:
        rows.append(("Media", "Anomalia de trafico",
                     f"{an['hour']} del {an['date']}: {an['requests']} peticiones (z~{an['z']})"))

    out = ["## Resumen de hallazgos", ""]
    if not rows:
        return "\n".join(out + ["Sin hallazgos.", ""])
    out += ["| Severidad | Categoria | Hallazgo |", "|---|---|---|"]
    out += [f"| {s} | {c} | {d} |" for s, c, d in rows]
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Genera report.md a partir de auth.log y access.log.")
    ap.add_argument("--auth", default="auth.log", help="Ruta a auth.log (default: auth.log)")
    ap.add_argument("--access", default="access.log", help="Ruta a access.log (default: access.log)")
    ap.add_argument("--output", default="report.md", help="Archivo de salida (default: report.md)")
    args = ap.parse_args()
    try:
        a = analyze_auth(args.auth)
        w = analyze_web(args.access)
    except OSError as e:
        print(f"Error leyendo logs: {e}", file=sys.stderr)
        return 1

    doc = "\n".join([
        "# Informe de analisis de logs", "",
        f"Generado: {datetime.now():%Y-%m-%d %H:%M} | Archivos: `{args.auth}`, `{args.access}`", "",
        summary(a, w), auth_md(a), web_md(w),
    ])
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(doc)
    print(f"Informe escrito en {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

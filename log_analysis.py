#!/usr/bin/env python3
"""Parte 3B-3D: analisis de access.log (ataques web, top IPs, status y anomalias 3-sigma).

Ejemplo:
  python3 log_analysis.py access.log
  python3 log_analysis.py access.log --sigma 3.0 --json
"""
import argparse
import json
import re
import statistics
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import unquote_plus

# La ruta admite espacios: termina en el ' HTTP/x.y"' final, no en el primer espacio
LOG_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>.*?)(?: HTTP/[\d.]+)?" (?P<status>\d{3}) (?P<size>\S+)'
)
TS_HOUR = re.compile(r"^(?P<date>\d{2}/\w{3}/\d{4}):(?P<hour>\d{2}):")

ATTACKS = {
    "sqli": re.compile(
        r"union(\s+all)?\s+select|select\s.+\sfrom\s|insert\s+into|drop\s+table|"
        r"'\s*or\s+'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b|sleep\s*\(|benchmark\s*\(|information_schema"
    ),
    "path_traversal": re.compile(r"\.\./|\.\.\\|/etc/(passwd|shadow|hosts)\b|\\windows\\|boot\.ini"),
    "xss": re.compile(r"<\s*script|<\s*svg|<\s*img[^>]*\son\w+\s*=|\son\w+\s*=|javascript\s*:|<\s*iframe"),
    "command_injection": re.compile(
        r"\b(cmd|exec|shell|command)=|[;|`]\s*(id|whoami|uname|cat|ls|wget|curl|nc|bash|sh|ping)\b|\$\("
    ),
}


def normalize(path: str, rounds: int = 3) -> str:
    """Decodifica hasta `rounds` veces (doble/triple encoding), quita comentarios SQL y pasa a minusculas."""
    s = path
    for _ in range(rounds):
        decoded = unquote_plus(s)
        if decoded == s:
            break
        s = decoded
    s = re.sub(r"/\*.*?\*/", "", s)   # UN/**/ION -> UNION
    return s.lower()


def classify(path: str) -> list[str]:
    norm = normalize(path)
    return [family for family, rx in ATTACKS.items() if rx.search(norm)]


def analyze_web(path: str, sigma: float = 3.0) -> dict:
    ip_counts: Counter = Counter()
    status_counts: Counter = Counter()
    hourly: Counter = Counter()
    suspicious = []
    unparsed = 0

    with Path(path).open(encoding="utf-8", errors="replace") as f:
        for line in f:
            m = LOG_LINE.match(line)
            if not m:
                unparsed += 1
                continue
            ip, status, req = m.group("ip"), m.group("status"), m.group("path")
            ip_counts[ip] += 1
            status_counts[status] += 1
            if h := TS_HOUR.match(m.group("ts")):
                hourly[(h.group("date"), int(h.group("hour")))] += 1
            if families := classify(req):
                suspicious.append({"ip": ip, "families": families, "status": status,
                                   "time": m.group("ts"), "path": req})

    # Rellenar con 0 las horas sin trafico de cada dia observado
    for date in {d for d, _ in hourly}:
        for hour in range(24):
            hourly.setdefault((date, hour), 0)

    anomalies, stats = [], {}
    counts = list(hourly.values())
    if len(counts) >= 2:
        mean, stdev = statistics.mean(counts), statistics.stdev(counts)
        stats = {"hours": len(counts), "mean": round(mean, 1), "stdev": round(stdev, 1),
                 "threshold_requests": round(mean + sigma * stdev, 1),
                 "max_possible_z": round((len(counts) - 1) / len(counts) ** 0.5, 2)}
        if stdev > 0:
            for (date, hour), n in sorted(hourly.items()):
                z = (n - mean) / stdev
                if z > sigma:
                    anomalies.append({"date": date, "hour": f"{hour:02d}:00", "requests": n, "z": round(z, 2)})

    return {
        "lines_parsed": sum(ip_counts.values()),
        "lines_unparsed": unparsed,
        "top_ips": ip_counts.most_common(5),
        "status_distribution": dict(sorted(status_counts.items())),
        "suspicious_requests": suspicious,
        "suspicious_by_family": dict(Counter(f for s in suspicious for f in s["families"])),
        "hourly_stats": stats,
        "anomalies": anomalies,
        "params": {"sigma": sigma},
    }


def anomaly_lines(r: dict) -> list[str]:
    sigma = r["params"]["sigma"]
    return [f"[ANOMALY] {a['hour']} ({a['date']}) - {a['requests']} requests "
            f"(z~{a['z']}σ, threshold={sigma}σ)" for a in r["anomalies"]]


def to_markdown(r: dict) -> str:
    out = ["## Trafico web (access.log)", "",
           f"- Lineas analizadas: **{r['lines_parsed']}** (no reconocidas: {r['lines_unparsed']})", ""]

    out += [f"### Peticiones sospechosas ({len(r['suspicious_requests'])})", ""]
    if r["suspicious_requests"]:
        out += ["| Familia | Peticiones |", "|---|---:|"]
        out += [f"| {fam} | {n} |" for fam, n in sorted(r["suspicious_by_family"].items())]
        out += ["", "| IP | Familia | Status | Hora | Ruta (tal como llego) |", "|---|---|---|---|---|"]
        for s in r["suspicious_requests"]:
            out.append(f"| {s['ip']} | {', '.join(s['families'])} | {s['status']} | {s['time']} | `{s['path']}` |")
        out += ["", "Nota: una coincidencia es triaje, no veredicto; cada hit requiere revision o una segunda senal."]
    else:
        out.append("Ninguna.")

    out += ["", "### Top 5 IPs por volumen", "", "| IP | Peticiones |", "|---|---:|"]
    out += [f"| {ip} | {n} |" for ip, n in r["top_ips"]]

    out += ["", "### Distribucion de codigos HTTP", "", "| Status | Peticiones |", "|---|---:|"]
    out += [f"| {st} | {n} |" for st, n in r["status_distribution"].items()]

    st = r["hourly_stats"]
    out += ["", "### Anomalias de trafico por hora (regla 3-sigma)", ""]
    if st:
        out.append(f"- Horas: {st['hours']}, media: {st['mean']}, desviacion: {st['stdev']}, "
                   f"umbral: {st['threshold_requests']} peticiones/hora "
                   f"(z maximo alcanzable con {st['hours']} muestras: {st['max_possible_z']})")
    out += [""] + ([f"    {line}" for line in anomaly_lines(r)] or ["Ninguna hora supera el umbral."])
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Analiza access.log: ataques web, top IPs, status y anomalias.")
    ap.add_argument("logfile", help="Ruta a access.log")
    ap.add_argument("--sigma", type=float, default=3.0, help="Umbral en desviaciones estandar (default 3.0)")
    ap.add_argument("--json", action="store_true", help="Salida JSON en vez de Markdown")
    args = ap.parse_args()
    try:
        result = analyze_web(args.logfile, args.sigma)
    except OSError as e:
        print(f"Error leyendo {args.logfile}: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for line in anomaly_lines(result):
            print(line, file=sys.stderr)
        print(to_markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())

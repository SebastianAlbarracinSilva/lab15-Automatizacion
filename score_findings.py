#!/usr/bin/env python3
"""Parte 3 (scoring): compara planted.json con lo que detectan los analizadores y escribe findings_score.md."""
import json
import re
from urllib.parse import unquote

from auth_analysis import analyze_auth
from log_analysis import analyze_web

# Primer borrador = patrones de la seccion de teoria
THEORY_ATTACKS = re.compile(
    r"(union.*select|insert.*into|drop\s+table|\.\./|\.\.\\|<script|cmd=|exec=|shell=)", re.IGNORECASE)
NAIVE_FAIL = re.compile(r"Failed password for \S+ from \d+\.\d+\.\d+\.\d+")
FULL_FAIL = re.compile(r"Failed password for (?:invalid user )?\S+ from \d+\.\d+\.\d+\.\d+")

FIX_BY_TRAIT = [
    ("%25", "doble codificacion: decodificar en bucle (hasta 3 rondas) antes de buscar"),
    ("/**/", "comentario SQL que parte la palabra: eliminar /**/ antes de buscar union...select"),
    ("svg", "XSS sin <script: agregar <svg, on<evento>=, javascript: e <iframe"),
]


def main() -> None:
    planted = json.load(open("planted.json", encoding="utf-8"))
    a, w = analyze_auth("auth.log"), analyze_web("access.log")
    attackers = planted["attacker_ips"]
    rows, fps, fixes = [], [], []

    brute = {b["ip"]: b["failures"] for b in a["brute_force_ips"]}
    for ip, n in attackers.items():
        rows.append((f"Fuerza bruta desde {ip} ({n} fallos)", ip in brute, f"detectados {brute.get(ip, 0)} fallos"))

    invalid = {u["user"] for u in a["targeted_users"] if not u["account_exists"]}
    planted_invalid = {"test", "oracle", "admin1"}
    rows.append((f"{planted['invalid_user_lines_added']} lineas 'invalid user' (test/oracle/admin1)",
                 planted_invalid <= invalid, f"marcados como inexistentes: {sorted(planted_invalid & invalid)}"))

    breached = planted["successful_login_after_failures"]
    hit = [b for b in a["success_after_failures"] if b["ip"] == breached]
    rows.append((f"Login exitoso tras fallos desde {breached}", bool(hit),
                 f"{hit[0]['time']}, {hit[0]['failures_before']} fallos previos" if hit else "-"))

    spike = planted["traffic_spike"]
    spike_hour = f"{spike['hour']:02d}:00"
    an = [x for x in w["anomalies"] if x["hour"] == spike_hour]
    rows.append((f"Pico de trafico a las {spike_hour} desde {spike['source_ip']}", bool(an),
                 f"z~{an[0]['z']}" if an else "-"))

    planted_paths = {p["path"] for p in planted["attack_paths"]}
    for p in planted["attack_paths"]:
        got = {s["ip"] for s in w["suspicious_requests"] if s["path"] == p["path"]}
        label = f"{p['family']}{' (custom)' if p['custom'] else ''}: `{p['path']}`"
        rows.append((label, set(p["sent_by"]) <= got, f"{len(got)}/{len(p['sent_by'])} IPs"))
        if not THEORY_ATTACKS.search(unquote(p["path"])):
            fix = next((f for trait, f in FIX_BY_TRAIT if trait in p["path"].lower()), "patron ampliado")
            fixes.append(f"- `{p['path']}`: el primer borrador (regex de la teoria + un solo unquote) NO lo detecta. "
                         f"Causa: patron debil. Arreglo: {fix}.")

    fps += [f"- Fuerza bruta: {ip}" for ip in brute if ip not in attackers]
    fps += [f"- Login tras fallos: {b['ip']}" for b in a["success_after_failures"] if b["ip"] != breached]
    fps += [f"- Peticion web: {s['ip']} `{s['path']}`" for s in w["suspicious_requests"]
            if s["path"] not in planted_paths or s["ip"] not in attackers]
    fps += [f"- Anomalia: {x['hour']}" for x in w["anomalies"] if x["hour"] != spike_hour]

    raw = open("auth.log", encoding="utf-8", errors="replace").read()
    naive, full = len(NAIVE_FAIL.findall(raw)), len(FULL_FAIL.findall(raw))
    fixes.append(f"- auth.log: el patron sin `(?:invalid user )?` cuenta {naive} fallos frente a {full}; "
                 f"pierde {full - naive} intentos contra cuentas inexistentes. Causa: patron debil. "
                 f"Arreglo: 'invalid user' opcional en el regex.")
    fixes.append("- access.log: el regex de linea de la teoria corta la ruta en el primer espacio. "
                 "Arreglo preventivo: la ruta termina en ' HTTP/x.y\"', no en el primer espacio.")
    st = w["hourly_stats"]
    fixes.append(f"- 3-sigma: el pico se detecto con z~{an[0]['z'] if an else '-'}, cerca del maximo alcanzable "
                 f"({st.get('max_possible_z')}) con {st.get('hours')} muestras. Limite del metodo, no del patron: "
                 f"con 10 horas o menos ningun pico supera 3 sigma. Mitigacion: baseline robusta (mediana/MAD) "
                 f"o comparacion contra la misma hora de dias anteriores.")

    detected = sum(1 for _, ok, _ in rows if ok)
    out = ["# Findings score: planted.json vs report.md", "",
           f"Detectados: **{detected}/{len(rows)}** | Falsos positivos: **{len(fps)}**", "",
           "## Elementos plantados", "", "| Elemento plantado | Detectado | Detalle |", "|---|---|---|"]
    out += [f"| {item} | {'si' if ok else '**NO**'} | {d} |" for item, ok, d in rows]
    out += ["", "## Elementos del informe que no fueron plantados (falsos positivos)", ""]
    out += fps or ["Ninguno: todo lo reportado corresponde a algo plantado."]
    out += ["", "## Fallos del primer borrador y arreglos", ""] + fixes
    open("findings_score.md", "w", encoding="utf-8").write("\n".join(out) + "\n")
    print(f"findings_score.md: {detected}/{len(rows)} detectados, {len(fps)} falsos positivos")


if __name__ == "__main__":
    main()

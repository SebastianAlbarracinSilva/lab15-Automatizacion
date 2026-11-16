#!/usr/bin/env python3
"""Parte 4: recon.py - reconocimiento multi-etapa de un dominio o una IP, con audit log.

Ejemplos:
  python3 recon.py example.com --verbose
  python3 recon.py 192.168.216.128 --output sample_output/ip
  python3 recon.py 192.168.216.128 --ports 1-1024
"""
import argparse
import ipaddress
import json
import logging
import re
import shlex
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy (CSP)",
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "x-frame-options": "X-Frame-Options",
}
INFO_HEADERS = ["server", "x-powered-by"]

WHOIS_DOMAIN_FIELDS = {
    "registrar": ["Registrar", "Sponsoring Registrar", "registrar"],
    "registration_date": ["Creation Date", "Created", "Registered on", "Registration Time", "created"],
    "expiry_date": ["Registry Expiry Date", "Registrar Registration Expiration Date",
                    "Expiry Date", "Expiration Date", "paid-till", "expires"],
    "registrant_organization": ["Registrant Organization", "Registrant Organisation", "Registrant", "org"],
}
WHOIS_IP_FIELDS = {
    "organization": ["OrgName", "org-name", "Organization", "owner", "descr", "netname"],
    "country": ["Country", "country"],
    "network": ["NetRange", "inetnum", "CIDR"],
}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)

audit = logging.getLogger("audit")
VERBOSE = False


def progress(msg: str) -> None:
    if VERBOSE:
        print(f"[*] {msg}", file=sys.stderr)


def setup_audit(outdir: Path) -> None:
    handler = logging.FileHandler(outdir / "audit.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    audit.addHandler(handler)
    audit.setLevel(logging.INFO)


# ---------- Ejecucion auditada (requisito 2) ----------
def run_logged(cmd: list[str], timeout: int = 120) -> dict:
    """Ejecuta cmd, registra comando, resultado y duracion en audit.log y devuelve la salida."""
    cmd_str = shlex.join(cmd)
    audit.info("RUN %s", cmd_str)
    progress(f"ejecutando: {cmd_str}")
    start = time.perf_counter()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        audit.error("FAIL %s | herramienta no encontrada", cmd_str)
        return {"ok": False, "returncode": None, "stdout": "", "stderr": "", "error": f"{cmd[0]} no esta instalado"}
    except subprocess.TimeoutExpired:
        audit.error("FAIL %s | timeout tras %ss", cmd_str, timeout)
        return {"ok": False, "returncode": None, "stdout": "", "stderr": "", "error": f"timeout ({timeout}s)"}
    elapsed = time.perf_counter() - start
    ok = p.returncode == 0
    (audit.info if ok else audit.error)(
        "%s %s | exit=%s | %.2fs | stdout=%dB stderr=%dB",
        "OK" if ok else "FAIL", cmd_str, p.returncode, elapsed, len(p.stdout), len(p.stderr))
    error = None if ok else (p.stderr.strip()[:300] or p.stdout.strip()[:300] or f"exit {p.returncode}")
    return {"ok": ok, "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr, "error": error}


def run_stage(name: str, func, *args) -> dict:
    """Una etapa que falla (incluso por excepcion) nunca detiene a las demas."""
    audit.info("STAGE %s start", name)
    progress(f"etapa {name}")
    try:
        result = func(*args)
    except Exception as e:
        audit.exception("STAGE %s crashed", name)
        result = {"status": "error", "error": f"{type(e).__name__}: {e}"}
    audit.info("STAGE %s end status=%s", name, result.get("status"))
    return result


# ---------- Etapas ----------
def first_match(text: str, labels: list[str]) -> str | None:
    for label in labels:
        if m := re.search(rf"^\s*(?:{label})\s*:\s*(.+?)\s*$", text, re.IGNORECASE | re.MULTILINE):
            return m.group(1)
    return None


def stage_whois(target: str, mode: str) -> dict:
    r = run_logged(["whois", target], timeout=60)
    if not r["stdout"].strip():
        return {"status": "error", "error": r["error"] or "whois sin salida"}
    fields = WHOIS_IP_FIELDS if mode == "ip" else WHOIS_DOMAIN_FIELDS
    data = {key: first_match(r["stdout"], labels) for key, labels in fields.items()}
    return {"status": "ok" if all(data.values()) else "partial", **data}


def dig_short(args: list[str]) -> tuple[list[str], str | None]:
    r = run_logged(["dig", "+short", "+time=3", "+tries=2", *args], timeout=20)
    lines = [l.strip() for l in r["stdout"].splitlines() if l.strip() and not l.startswith(";")]
    return (lines, None) if r["ok"] else ([], r["error"])


def stage_dig_domain(domain: str) -> dict:
    records, errors = {}, {}
    for rtype in ("A", "MX", "NS", "TXT"):
        records[rtype], err = dig_short([domain, rtype])
        if err:
            errors[rtype] = err
    status = "ok" if not errors else ("error" if len(errors) == 4 else "partial")
    return {"status": status, "records": records, **({"errors": errors} if errors else {})}


def stage_dig_reverse(ip: str) -> dict:
    names, err = dig_short(["-x", ip])
    if err:
        return {"status": "error", "error": err}
    return {"status": "ok", "reverse_dns": [n.rstrip(".") for n in names]}


def parse_headers(text: str) -> tuple[str | None, dict]:
    """Con -L hay un bloque por redireccion: se usa el ultimo (la respuesta final)."""
    blocks = [b for b in re.split(r"\r?\n\r?\n", text.strip()) if b.strip()]
    if not blocks:
        return None, {}
    lines = blocks[-1].splitlines()
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return lines[0].strip(), headers


def stage_curl(domain: str) -> dict:
    last_error = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        r = run_logged(["curl", "-sS", "-I", "-L", "--max-time", "15", url], timeout=30)
        if r["ok"] and r["stdout"].strip():
            status_line, h = parse_headers(r["stdout"])
            return {
                "status": "ok",
                "url": url,
                "status_line": status_line,
                "headers": {k: h.get(k) for k in INFO_HEADERS + list(SECURITY_HEADERS)},
                "missing_security_headers": [label for k, label in SECURITY_HEADERS.items() if k not in h],
            }
        last_error = r["error"]
    return {"status": "error", "error": last_error}


def stage_nmap(ip: str, ports: str | None) -> dict:
    port_args = ["-p", ports] if ports else ["--top-ports", "100"]
    cmd = ["nmap", "-sV", "--open", *port_args, "-oX", "-", ip]
    r = run_logged(cmd, timeout=900)
    if not r["ok"]:
        return {"status": "error", "error": r["error"]}
    try:
        root = ET.fromstring(r["stdout"])
    except ET.ParseError as e:
        return {"status": "error", "error": f"XML invalido: {e}"}

    hosts = []
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host.find("address[@addrtype='ipv6']")
        if addr is None:
            continue
        hostname = host.find("hostnames/hostname")
        open_ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            version = " ".join(v for v in (svc.get("product"), svc.get("version")) if v) if svc is not None else ""
            open_ports.append({"port": int(port.get("portid")),
                               "service": svc.get("name") if svc is not None else None,
                               "version": version or None})
        hosts.append({"ip": addr.get("addr"),
                      "hostname": hostname.get("name") if hostname is not None else None,
                      "open_ports": sorted(open_ports, key=lambda p: p["port"])})
    return {"status": "ok", "scan_args": " ".join(cmd[1:-1]), "hosts": hosts}


# ---------- Informe (requisito 6) ----------
def md(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def headline(tool: str, r: dict) -> str:
    if r.get("status") == "error":
        return f"error: {md(r.get('error'))}"
    if tool == "whois":
        if "organization" in r:
            return md(f"{r.get('organization') or '?'} ({r.get('country') or '?'})")
        return md(f"registrar: {r.get('registrar') or '?'}; expira: {r.get('expiry_date') or '?'}")
    if tool == "dig":
        if "reverse_dns" in r:
            return md(", ".join(r["reverse_dns"]) or "sin registro PTR")
        return ", ".join(f"{t}: {len(v)}" for t, v in r["records"].items())
    if tool == "curl":
        missing = r["missing_security_headers"]
        tail = f"faltan: {', '.join(missing)}" if missing else "cabeceras de seguridad presentes"
        return md(f"{r['status_line']}; {tail}")
    if tool == "nmap":
        ports = [f"{p['port']}/{p['service']}" for h in r["hosts"] for p in h["open_ports"]]
        return f"{len(ports)} puertos abiertos: {', '.join(ports)}" if ports else "sin puertos abiertos en los puertos probados"
    return ""


def build_report(res: dict) -> str:
    meta = res["meta"]
    tools = [k for k in res if k != "meta"]
    out = [f"# Informe de reconocimiento: {meta['target']}", "",
           f"- Modo: **{meta['mode']}** (reconocimiento activo: envia paquetes al objetivo)",
           f"- Inicio: {meta['started']} | Fin: {meta['finished']}", "",
           "## Resumen", "", "| Etapa | Estado | Hallazgo principal |", "|---|---|---|"]
    out += [f"| {t} | {res[t].get('status')} | {headline(t, res[t])} |" for t in tools]

    if "nmap" in res:
        r = res["nmap"]
        out += ["", "## Puertos abiertos", ""]
        rows = [(h["ip"], p) for h in r.get("hosts", []) for p in h["open_ports"]]
        if rows:
            out += [f"Escaneo: `nmap {r['scan_args']}`", "",
                    "| Host | Puerto | Servicio | Version |", "|---|---:|---|---|"]
            out += [f"| {ip} | {p['port']} | {md(p['service'] or '-')} | {md(p['version'] or '-')} |" for ip, p in rows]
            out += ["", "Nota: solo se probaron los puertos indicados; un puerto no listado no esta necesariamente cerrado."]
        else:
            out.append("Sin puertos abiertos o etapa con error (ver resumen).")

    if "dig" in res and "records" in res["dig"]:
        out += ["", "## Registros DNS", "", "| Tipo | Valor |", "|---|---|"]
        for rtype, values in res["dig"]["records"].items():
            out += [f"| {rtype} | {md(v)} |" for v in (values or ["(sin registros)"])]
    elif "dig" in res and "reverse_dns" in res["dig"]:
        out += ["", "## DNS inverso", "", ", ".join(res["dig"]["reverse_dns"]) or "Sin registro PTR."]

    if res.get("whois", {}).get("status") in ("ok", "partial"):
        out += ["", "## WHOIS", "", "| Campo | Valor |", "|---|---|"]
        out += [f"| {k} | {md(v) if v else '(no encontrado)'} |"
                for k, v in res["whois"].items() if k not in ("status", "error")]

    if res.get("curl", {}).get("status") == "ok":
        c = res["curl"]
        out += ["", f"## Cabeceras HTTP ({c['url']})", "", f"Respuesta: `{md(c['status_line'])}`", "",
                "| Cabecera | Valor |", "|---|---|"]
        out += [f"| {k} | {md(v) if v else '(ausente)'} |" for k, v in c["headers"].items()]
        out += ["", "### Cabeceras de seguridad ausentes", ""]
        out += [f"- {h}" for h in c["missing_security_headers"]] or ["Ninguna: CSP, HSTS y X-Frame-Options presentes."]
        disclosed = [k for k in INFO_HEADERS if c["headers"].get(k)]
        if disclosed:
            out += ["", f"Divulgacion de software: {', '.join(disclosed)} presente(s); "
                        "revisar si exponen version."]

    errors = [(t, res[t].get("error") or res[t].get("errors")) for t in tools if res[t].get("status") != "ok"]
    if errors:
        out += ["", "## Etapas con error o incompletas", ""]
        out += [f"- **{t}**: {md(e) if e else 'datos parciales'}" for t, e in errors]
    return "\n".join(out) + "\n"


# ---------- CLI (requisito 1) ----------
def detect_mode(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser(description="Reconocimiento multi-etapa de un dominio o una IP.")
    ap.add_argument("target", help="Nombre de dominio o direccion IP")
    ap.add_argument("--mode", choices=["domain", "ip"], help="Modo (se detecta automaticamente si se omite)")
    ap.add_argument("--output", help="Directorio de salida (default: ./recon_<target>_<timestamp>/)")
    ap.add_argument("--ports", help="Puertos para nmap en modo IP (default: --top-ports 100)")
    ap.add_argument("--verbose", action="store_true", help="Muestra el progreso en stderr")
    args = ap.parse_args()
    VERBOSE = args.verbose

    target = args.target.strip()
    mode = args.mode or detect_mode(target)
    if mode == "ip" and detect_mode(target) != "ip":
        ap.error(f"'{target}' no es una direccion IP valida")
    if mode == "domain" and not DOMAIN_RE.match(target):
        ap.error(f"'{target}' no es un nombre de dominio valido")

    started = datetime.now()
    outdir = Path(args.output or f"recon_{target.replace(':', '_')}_{started:%Y%m%d_%H%M%S}")
    outdir.mkdir(parents=True, exist_ok=True)
    setup_audit(outdir)
    audit.info("START recon target=%s mode=%s argv=%s", target, mode, shlex.join(sys.argv))

    results: dict = {"meta": {"target": target, "mode": mode, "started": started.isoformat(timespec="seconds")}}
    if mode == "domain":
        results["whois"] = run_stage("whois", stage_whois, target, mode)
        results["dig"] = run_stage("dig", stage_dig_domain, target)
        results["curl"] = run_stage("curl", stage_curl, target)
    else:
        results["nmap"] = run_stage("nmap", stage_nmap, target, args.ports)
        results["dig"] = run_stage("dig", stage_dig_reverse, target)
        results["whois"] = run_stage("whois", stage_whois, target, mode)
    results["meta"]["finished"] = datetime.now().isoformat(timespec="seconds")

    for name, content in (("results.json", json.dumps(results, indent=2, ensure_ascii=False) + "\n"),
                          ("report.md", build_report(results))):
        (outdir / name).write_text(content, encoding="utf-8")
        audit.info("WRITE %s", outdir / name)

    failed = [k for k, v in results.items() if k != "meta" and v.get("status") == "error"]
    audit.info("END recon target=%s failed_stages=%s", target, failed or "none")
    print(f"Resultados en {outdir}/ (results.json, report.md, audit.log)"
          + (f" | etapas con error: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

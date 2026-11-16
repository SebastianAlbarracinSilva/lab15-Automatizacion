#!/usr/bin/env python3
"""Parte 2: parsea el XML de nmap (-oX), enriquece con ssh-keyscan y escribe JSON.

Ejemplo:
  python3 parse_scan.py --input scan.xml --output hosts.json
"""
import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET


def service_version(svc: ET.Element | None) -> str | None:
    """'OpenSSH 10.6p1 Debian 1' a partir de los atributos product y version."""
    if svc is None:
        return None
    text = " ".join(v for v in (svc.get("product"), svc.get("version")) if v)
    return text or None


def parse_hosts(xml_path: str) -> list[dict]:
    try:
        root = ET.parse(xml_path).getroot()
    except (OSError, ET.ParseError) as e:
        sys.exit(f"Error leyendo {xml_path}: {e}")

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Elegir la direccion por addrtype, no la primera <address> (puede ser la MAC)
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue

        hostname_el = host.find("hostnames/hostname")
        open_ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            open_ports.append({
                "port": int(port.get("portid")),
                "service": svc.get("name") if svc is not None else None,
                "version": service_version(svc),
            })

        hosts.append({
            "ip": addr_el.get("addr"),
            "hostname": hostname_el.get("name") if hostname_el is not None else None,
            "open_ports": sorted(open_ports, key=lambda p: p["port"]),
        })
    return hosts


def ssh_key_types(ip: str, timeout: int) -> tuple[list[str] | None, str | None]:
    """Ejecuta ssh-keyscan y devuelve (tipos_de_llave, error)."""
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-T", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except FileNotFoundError:
        return None, "ssh-keyscan no esta instalado"

    types: list[str] = []
    for line in result.stdout.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()          # host  tipo_de_llave  llave_base64
        if len(fields) >= 3 and fields[1] not in types:
            types.append(fields[1])
    if not types:
        return None, result.stderr.strip() or f"sin respuesta (exit {result.returncode})"
    return types, None


def main() -> int:
    ap = argparse.ArgumentParser(description="Parsea XML de nmap y enriquece con ssh-keyscan.")
    ap.add_argument("--input", required=True, help="Archivo XML de nmap (-oX)")
    ap.add_argument("--output", default="hosts.json", help="Archivo JSON de salida (default: hosts.json)")
    ap.add_argument("--keyscan-timeout", type=int, default=5, help="Timeout de ssh-keyscan en segundos (default: 5)")
    args = ap.parse_args()

    hosts = parse_hosts(args.input)
    for host in hosts:
        if any(p["port"] == 22 for p in host["open_ports"]):
            types, error = ssh_key_types(host["ip"], args.keyscan_timeout)
            host["ssh_host_key_type"] = types
            if error:
                host["ssh_keyscan_error"] = error
                print(f"[!] ssh-keyscan fallo en {host['ip']}: {error}", file=sys.stderr)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(hosts, f, indent=2)
    print(f"{len(hosts)} host(s) escritos en {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

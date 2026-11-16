#!/usr/bin/env python3
"""Parte 1: escaner de puertos TCP concurrente (asyncio + semaforo).

Ejemplos:
  python3 scanner.py 192.168.216.128
  python3 scanner.py 192.168.216.128 --ports 22,80,100-1024 --rate 500 --output scan.json
"""
import argparse
import asyncio
import json
import random
import sys
import time
from collections import Counter
from datetime import datetime


def parse_ports(spec: str) -> list[int]:
    """Acepta '22,80,443', '1-1024' o mezclas como '22,100-200'."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = sorted((int(lo_s), int(hi_s)))
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    invalid = [p for p in ports if not 1 <= p <= 65535]
    if invalid or not ports:
        raise argparse.ArgumentTypeError(f"rango de puertos invalido: {spec}")
    return sorted(ports)


async def probe(host: str, port: int, timeout: float) -> str:
    """Devuelve open / closed / filtered / error:<errno>. Nunca convierte un error en 'closed'."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except ConnectionRefusedError:
        return "closed"            # llego un RST
    except TimeoutError:
        return "filtered"          # silencio: descartado, filtrado o perdido
    except OSError as e:
        return f"error:{e.errno}"  # p. ej. 24 = EMFILE (demasiados archivos abiertos)
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return "open"


async def scan(host: str, ports: list[int], rate: int, timeout: float, jitter: float) -> list[tuple[int, str]]:
    semaphore = asyncio.Semaphore(rate)

    async def limited(port: int) -> tuple[int, str]:
        async with semaphore:
            if jitter > 0:
                await asyncio.sleep(random.uniform(0, jitter))
            return port, await probe(host, port, timeout)

    return await asyncio.gather(*(limited(p) for p in ports))


def main() -> int:
    ap = argparse.ArgumentParser(description="Escaner de puertos TCP concurrente (connect scan, sin root).")
    ap.add_argument("target", help="Direccion IP a escanear")
    ap.add_argument("--ports", type=parse_ports, default=parse_ports("1-1024"),
                    help="Puertos, p. ej. 1-1024 o 22,80,443 (default: 1-1024)")
    ap.add_argument("--rate", type=int, default=200, help="Maximo de conexiones concurrentes (default: 200)")
    ap.add_argument("--timeout", type=float, default=0.5, help="Timeout por puerto en segundos (default: 0.5)")
    ap.add_argument("--jitter", type=float, default=0.0,
                    help="Retardo aleatorio maximo (s) antes de cada sonda (default: 0)")
    ap.add_argument("--output", help="Archivo JSON de salida (default: stdout)")
    args = ap.parse_args()
    if args.rate < 1:
        ap.error("--rate debe ser >= 1")

    timestamp = datetime.now().isoformat(timespec="seconds")
    start = time.perf_counter()
    results = asyncio.run(scan(args.target, args.ports, args.rate, args.timeout, args.jitter))
    elapsed = time.perf_counter() - start

    open_ports = sorted(p for p, s in results if s == "open")
    error_ports = sorted(p for p, s in results if s.startswith("error"))
    outcomes = Counter("error" if s.startswith("error") else s for _, s in results)
    error_codes = Counter(s.split(":", 1)[1] for _, s in results if s.startswith("error"))

    report = {
        "target": args.target,
        "scan_time_seconds": round(elapsed, 2),
        "timestamp": timestamp,
        "open_ports": open_ports,
        "rate": args.rate,
        "ports_scanned": len(args.ports),
        "outcomes": dict(outcomes),
        "error_codes": dict(error_codes),
        "error_ports": error_ports,
    }
    text = json.dumps(report, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"[rate={args.rate}] {len(args.ports)} puertos en {elapsed:.2f}s | abiertos={open_ports} "
              f"| resultados={dict(outcomes)} -> {args.output}", file=sys.stderr)
    else:
        print(text)

    if error_ports:
        print(f"AVISO: {len(error_ports)} puertos con error {dict(error_codes)}: resultado INCOMPLETO. "
              f"Reescanea esos puertos con un --rate menor.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

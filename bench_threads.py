import socket
import time
from concurrent.futures import ThreadPoolExecutor

HOST = "192.168.216.128"
EXPECTED = {22, 210, 555, 888}

def scan_port(args: tuple[str, int]) -> int | None:
    host, port = args
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            return port
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

print(f"{'workers':>8} | {'tiempo (s)':>10} | encontrados | perdidos")
for workers in (50, 200, 500):
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = ex.map(scan_port, [(HOST, p) for p in range(1, 1025)])
    found = sorted(p for p in results if p is not None)
    elapsed = time.perf_counter() - start
    missed = sorted(EXPECTED - set(found))
    print(f"{workers:>8} | {elapsed:>10.2f} | {found} | {missed}")

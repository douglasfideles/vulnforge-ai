import socket
import time

from vulnforge.models import ProbeResult


def transport_probe(target: str, port: int, transport: str) -> ProbeResult:
    start = time.monotonic()
    sock_type = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
    try:
        with socket.socket(socket.AF_INET, sock_type) as sock:
            sock.settimeout(1.0)
            if transport == "tcp":
                sock.connect((target, port))
            else:
                sock.sendto(b"", (target, port))
        return ProbeResult(responsive=True, detail=f"{transport.upper()} transport reachable", latency_ms=(time.monotonic()-start)*1000, source=transport)
    except OSError as exc:
        return ProbeResult(responsive=False, detail=str(exc), latency_ms=(time.monotonic()-start)*1000, source=transport)


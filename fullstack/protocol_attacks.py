from __future__ import annotations

import json
import socket
import time
from urllib.parse import urlsplit


def _status_from_raw(raw: bytes) -> int | None:
    try:
        return int(raw.split(b"\r\n", 1)[0].decode("ascii", "ignore").split()[1])
    except (ValueError, IndexError):
        return None


def _raw_http(base: str, wire: bytes, timeout: float = 3.0) -> tuple[bytes, float]:
    u = urlsplit(base)
    started = time.perf_counter()
    out = bytearray()
    with socket.create_connection((u.hostname or "127.0.0.1", u.port or 80), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(wire)
        while len(out) < 65536:
            try:
                chunk = sock.recv(min(8192, 65536 - len(out)))
            except socket.timeout:
                break
            if not chunk:
                break
            out.extend(chunk)
    return bytes(out), (time.perf_counter() - started) * 1000


def fragmented_chunked_exec(lab, Result):
    aid = lab.attack_id("chunked-fragment-v3")
    u = urlsplit(lab.cfg["mcp_gateway"])
    req = lab.tool(aid, "exec", {"command": "echo SAFE_MARKER", "probe": "chunked-fragment"})
    body = json.dumps(req, separators=(",", ":")).encode()
    cut = max(1, len(body) // 3)
    chunks = [body[:cut], body[cut : 2 * cut], body[2 * cut :]]
    path = (u.path.rstrip("/") + "/mcp") or "/mcp"
    wire = bytearray((f"POST {path} HTTP/1.1\r\n" f"Host: {u.hostname}\r\n" "Transfer-Encoding: chunked\r\n" "Content-Type: application/json\r\n" "mcp-method: tools/call\r\n" "X-Heraclitus-Agent: chunked-v3\r\n" f"X-Heraclitus-Run: {aid}\r\n" "Connection: close\r\n\r\n").encode())
    for chunk in chunks:
        wire.extend(f"{len(chunk):X}\r\n".encode()); wire.extend(chunk); wire.extend(b"\r\n")
    wire.extend(b"0\r\n\r\n")
    before = lab.tool_hits("exec")
    try:
        raw, ms = _raw_http(lab.cfg["mcp_gateway"], bytes(wire)); status = _status_from_raw(raw)
    except OSError as exc:
        raw, ms, status = repr(exc).encode(), 0.0, None
    after = lab.tool_hits("exec")
    delta = after - before if before is not None and after is not None else None
    passed = delta in {0, None} and status in {400, 401, 403, 405, 411, 413, 422, 501}
    result = Result(aid, "fragmented-http-chunked-exec", "mcp:http1-framing", "fragmented request cannot bypass restricted tool policy", f"HTTP {status}", passed, status=status, blocked=passed, upstream_delta=delta, detail=raw[:160].decode("utf-8", "replace"), duration_ms=ms, severity="high", tags=["protocol", "fragmentation", "chunked", "mcp"])
    lab.report(result)
    return result


def partial_body_drop(lab, Result):
    aid = lab.attack_id("partial-body-v3")
    u = urlsplit(lab.cfg["mcp_gateway"])
    req = lab.tool(aid, "exec", {"command": "echo SAFE_MARKER"})
    body = json.dumps(req).encode(); prefix = body[: max(1, len(body) // 2)]
    wire = (f"POST /mcp HTTP/1.1\r\nHost: {u.hostname}\r\nContent-Type: application/json\r\n" f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + prefix
    started = time.perf_counter()
    try:
        with socket.create_connection((u.hostname or "127.0.0.1", u.port or 80), timeout=2) as sock:
            sock.sendall(wire); time.sleep(0.05)
    except OSError:
        pass
    health_status, _, _ = lab.request(lab.cfg["agent_api"], "/api/v1/agent/status", headers=lab.auth_agent())
    passed = health_status == 200
    result = Result(aid, "partial-body-connection-drop", "mcp:http1-framing", "partial client body does not crash or wedge service", f"health={health_status}", passed, status=health_status, detail=f"sent={len(prefix)}/{len(body)} bytes", duration_ms=(time.perf_counter() - started) * 1000, severity="medium", tags=["protocol", "partial-write", "disconnect"])
    lab.report(result)
    return result

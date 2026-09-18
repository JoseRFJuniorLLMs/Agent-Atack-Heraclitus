from __future__ import annotations

import socket
import threading
import time
from urllib.parse import urlsplit

from fullstack.process_probe import delta, snapshot


def bounded_slow_connections(lab, Result, server_pid: int | None = None):
    """Bounded slow-client pressure. Never exceeds 64 sockets or 5 seconds."""
    aid = lab.attack_id("slow-connections-v3")
    count = max(2, min(int(lab.cfg.get("slow_connections", 16)), 64))
    hold = max(0.2, min(float(lab.cfg.get("slow_hold_seconds", 1.5)), 5.0))
    u = urlsplit(lab.cfg["mcp_gateway"])
    before = snapshot(server_pid)
    sockets: list[socket.socket] = []
    errors = 0
    started = time.perf_counter()
    try:
        for i in range(count):
            try:
                sock = socket.create_connection((u.hostname or "127.0.0.1", u.port or 80), timeout=2)
                sock.sendall(("POST /mcp HTTP/1.1\r\n" f"Host: {u.hostname}\r\n" "Content-Type: application/json\r\n" "Content-Length: 4096\r\n" f"X-Heraclitus-Agent: slow-{i}\r\n").encode())
                sockets.append(sock)
            except OSError:
                errors += 1
        time.sleep(hold)
    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass
    health_status, _, _ = lab.request(lab.cfg["agent_api"], "/api/v1/agent/status", headers=lab.auth_agent())
    alive = health_status == 200
    proc_delta = delta(before, snapshot(server_pid))
    result = Result(aid, "bounded-slow-connection-pressure", "mcp:tcp-resource", "service remains healthy after bounded slow sockets", f"health={health_status}; opened={len(sockets)}/{count}", alive, status=health_status, blocked=None, detail=f"errors={errors}; process_delta={proc_delta}", duration_ms=(time.perf_counter() - started) * 1000, severity="high", tags=["resource", "slow-client", "fd", "bounded"])
    lab.report(result)
    return result


def connection_churn(lab, Result, server_pid: int | None = None):
    """Rapid bounded TCP connect/disconnect churn."""
    aid = lab.attack_id("connection-churn-v3")
    n = max(8, min(int(lab.cfg.get("connection_churn", 128)), 1024))
    u = urlsplit(lab.cfg["mcp_gateway"])
    before = snapshot(server_pid)
    failures = 0
    lock = threading.Lock()
    started = time.perf_counter()
    def one() -> None:
        nonlocal failures
        try:
            with socket.create_connection((u.hostname or "127.0.0.1", u.port or 80), timeout=1):
                pass
        except OSError:
            with lock:
                failures += 1
    threads = [threading.Thread(target=one) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3)
    health_status, _, _ = lab.request(lab.cfg["agent_api"], "/api/v1/agent/status", headers=lab.auth_agent())
    alive = health_status == 200
    proc_delta = delta(before, snapshot(server_pid))
    result = Result(aid, "connection-churn", "mcp:tcp-resource", "service survives bounded rapid connect/disconnect churn", f"health={health_status}; failures={failures}/{n}", alive, status=health_status, detail=f"process_delta={proc_delta}", duration_ms=(time.perf_counter() - started) * 1000, severity="medium", tags=["resource", "connections", "fd", "churn"])
    lab.report(result)
    return result

from __future__ import annotations
import socket,threading,time
from urllib.parse import urlsplit
from metrics.process_probe import delta,snapshot
from .common import AttackResult

def bounded_slow_connections(ctx,server_pid=None):
    aid=ctx.attack_id("slow-connections"); count=max(2,min(int(ctx.cfg.get("slow_connections",16)),64)); hold=max(.2,min(float(ctx.cfg.get("slow_hold_seconds",1.5)),5.0)); u=urlsplit(str(ctx.cfg["mcp_gateway"])); before=snapshot(server_pid); sockets=[]; errors=0; started=time.perf_counter()
    try:
        for i in range(count):
            try:
                s=socket.create_connection((u.hostname or "127.0.0.1",u.port or 80),timeout=2); s.sendall(f"POST /mcp HTTP/1.1\r\nHost: {u.hostname}\r\nContent-Length: 4096\r\nX-Heraclitus-Agent: slow-{i}\r\n".encode()); sockets.append(s)
            except OSError: errors+=1
        time.sleep(hold)
    finally:
        for s in sockets:
            try:s.close()
            except OSError:pass
    alive=ctx.health(); d=delta(before,snapshot(server_pid)); return ctx.record(AttackResult(aid,"bounded-slow-connection-pressure","resource","mcp:tcp","service remains healthy after bounded zombie/slow sockets",f"health={alive}; opened={len(sockets)}/{count}",alive,"high",duration_ms=(time.perf_counter()-started)*1000,agent_id="slow-pool",detail=f"errors={errors}; process_delta={d}",tags=["slowloris-like","fd","bounded"]),native_probe=False)

def connection_churn(ctx,server_pid=None):
    aid=ctx.attack_id("conn-churn"); n=max(8,min(int(ctx.cfg.get("connection_churn",128)),1024)); u=urlsplit(str(ctx.cfg["mcp_gateway"])); before=snapshot(server_pid); failures=[0]; started=time.perf_counter()
    def one(_):
        try:
            with socket.create_connection((u.hostname or "127.0.0.1",u.port or 80),timeout=1):pass
        except OSError:failures[0]+=1
    ts=[threading.Thread(target=one,args=(i,)) for i in range(n)]
    for t in ts:t.start()
    for t in ts:t.join(timeout=3)
    alive=ctx.health(); d=delta(before,snapshot(server_pid)); return ctx.record(AttackResult(aid,"connection-churn","resource","mcp:tcp","service survives rapid connect/disconnect churn",f"health={alive}; failures={failures[0]}/{n}",alive,"medium",duration_ms=(time.perf_counter()-started)*1000,agent_id="churn",detail=f"process_delta={d}",tags=["connections","fd","churn"]),native_probe=False)
def run(ctx,server_pid=None):return [bounded_slow_connections(ctx,server_pid),connection_churn(ctx,server_pid)]

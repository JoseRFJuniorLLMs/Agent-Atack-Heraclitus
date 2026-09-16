from __future__ import annotations
import json
from urllib.parse import urlsplit
from .common import AttackResult, LabContext

def _status_from_raw(raw):
    try: return int(raw.split(b"\r\n",1)[0].decode("ascii","ignore").split()[1])
    except Exception: return None

def duplicate_json_keys(ctx):
    aid=ctx.attack_id("dup-json-key"); before=ctx.hits(); raw=('{"jsonrpc":"2.0","id":"%s","method":"tools/call","params":{"name":"lookup_vendor","name":"exec","arguments":{"command":"echo SAFE"}}}'%aid).encode(); s,b,ms=ctx.request(str(ctx.cfg["mcp_gateway"]),"/mcp","POST",raw,ctx.mcp_headers("dup-key",aid)); after=ctx.hits(); delta=None if before is None or after is None else after-before; passed=s in {400,403,422} and delta in {0,None}; return ctx.record(AttackResult(aid,"duplicate-json-key-differential","protocol","mcp:json-parser","ambiguous duplicate keys fail closed",f"HTTP {s}",passed,"high",s,passed,delta,duration_ms=ms,agent_id="dup-key",detail=ctx.reason(b) or "duplicate params.name",tags=["json","parser-differential"]))

def nul_byte_json(ctx):
    aid=ctx.attack_id("nul-json"); before=ctx.hits(); body=json.dumps(ctx.tool(aid,"exec",{"command":"echo SAFE"})).encode()+b"\x00{}"; s,b,ms=ctx.request(str(ctx.cfg["mcp_gateway"]),"/mcp","POST",body,ctx.mcp_headers("nul-json",aid)); after=ctx.hits(); delta=None if before is None or after is None else after-before; passed=s in {400,403,413,422} and delta in {0,None}; return ctx.record(AttackResult(aid,"nul-byte-json-framing","protocol","mcp:json-parser","trailing NUL/second frame rejected and no upstream",f"HTTP {s}",passed,"high",s,passed,delta,duration_ms=ms,agent_id="nul-json",detail=ctx.reason(b) or "NUL suffix",tags=["framing","nul","mcp"]))

def partial_body_close(ctx):
    aid=ctx.attack_id("partial-body"); u=urlsplit(str(ctx.cfg["mcp_gateway"])); path=(u.path.rstrip("/")+"/mcp") or "/mcp"; body=json.dumps(ctx.tool(aid,"exec",{"command":"echo SAFE"})).encode(); prefix=body[:max(1,len(body)//2)]; wire=(f"POST {path} HTTP/1.1\r\nHost: {u.hostname}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()+prefix; ms=ctx.close_partial(str(ctx.cfg["mcp_gateway"]),wire); alive=ctx.health(); return ctx.record(AttackResult(aid,"partial-body-connection-drop","protocol","mcp:http-framing","connection drop does not crash/hang service",f"health={alive}",alive,"medium",duration_ms=ms,agent_id="partial-client",detail=f"sent={len(prefix)}/{len(body)} bytes",tags=["fragmentation","partial-write"]),native_probe=False)

def fragmented_chunked_request(ctx):
    aid=ctx.attack_id("chunked-fragment"); u=urlsplit(str(ctx.cfg["mcp_gateway"])); path=(u.path.rstrip("/")+"/mcp") or "/mcp"; body=json.dumps(ctx.tool(aid,"exec",{"command":"echo SAFE"}),separators=(",",":")).encode(); cut=max(1,len(body)//3); chunks=[body[:cut],body[cut:2*cut],body[2*cut:]]; wire=bytearray((f"POST {path} HTTP/1.1\r\nHost: {u.hostname}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nmcp-method: tools/call\r\nX-Heraclitus-Agent: chunked-v3\r\nX-Heraclitus-Run: {aid}\r\nConnection: close\r\n\r\n").encode())
    for chunk in chunks: wire.extend(f"{len(chunk):X}\r\n".encode()); wire.extend(chunk); wire.extend(b"\r\n")
    wire.extend(b"0\r\n\r\n"); before=ctx.hits()
    try: raw,ms=ctx.raw_http(str(ctx.cfg["mcp_gateway"]),bytes(wire),timeout=3); s=_status_from_raw(raw)
    except Exception as exc: s,ms,raw=None,0.0,repr(exc).encode()
    after=ctx.hits(); delta=None if before is None or after is None else after-before; passed=s in {400,403,405,411,413,422,501} and delta in {0,None}; return ctx.record(AttackResult(aid,"fragmented-http-chunked-tools-call","protocol","mcp:http1","fragmentation cannot bypass restricted tool policy",f"HTTP {s}",passed,"high",s,passed,delta,duration_ms=ms,agent_id="chunked-v3",detail=raw[:120].decode("utf-8","replace"),tags=["fragmentation","chunked","mcp"]))

def content_type_confusion(ctx):
    aid=ctx.attack_id("content-type"); before=ctx.hits(); body=json.dumps(ctx.tool(aid,"exec",{"command":"echo SAFE"})).encode(); h=ctx.mcp_headers("ctype-v3",aid); h["Content-Type"]="text/plain"; s,b,ms=ctx.request(str(ctx.cfg["mcp_gateway"]),"/mcp","POST",body,h); after=ctx.hits(); delta=None if before is None or after is None else after-before; passed=delta in {0,None} and s in {400,401,403,415,422}; return ctx.record(AttackResult(aid,"content-type-confusion","protocol","mcp:content-type","text/plain cannot bypass exec policy",f"HTTP {s}",passed,"high",s,passed,delta,duration_ms=ms,agent_id="ctype-v3",detail=ctx.reason(b) or "text/plain JSON",tags=["content-type","parser-differential"]))

def run(ctx): return [duplicate_json_keys(ctx),nul_byte_json(ctx),partial_body_close(ctx),fragmented_chunked_request(ctx),content_type_confusion(ctx)]

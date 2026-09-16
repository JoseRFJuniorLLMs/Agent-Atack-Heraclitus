from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}

@dataclass
class AttackResult:
    attack_id: str
    vector: str
    category: str
    target: str
    expected: str
    observed: str
    passed: bool
    severity: str = "info"
    status: int | None = None
    blocked: bool | None = None
    upstream_delta: int | None = None
    evidence_lsn: int | None = None
    native_evidence: bool | None = None
    duration_ms: float = 0.0
    agent_id: str | None = None
    detail: str = ""
    tags: list[str] = field(default_factory=list)
    def to_dict(self) -> dict[str, Any]: return asdict(self)

class LabContext:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg; self.campaign = str(cfg.get("campaign") or f"v3-{int(time.time())}"); self.results=[]; self.sequence=0
        for key in ("core_rest","agent_api","otlp","mcp_gateway"):
            if key in cfg: self.assert_loopback_url(str(cfg[key]), key)
        if cfg.get("upstream_hits"): self.assert_loopback_url(str(cfg["upstream_hits"]), "upstream_hits")
        grpc_host=str(cfg.get("core_grpc_host","127.0.0.1"))
        if grpc_host not in LOOPBACK: raise SystemExit(f"RECUSADO: core_grpc_host deve ser loopback, veio {grpc_host!r}")
    @staticmethod
    def assert_loopback_url(url:str,label:str="endpoint") -> None:
        u=urlsplit(url)
        if u.scheme not in {"http","https"} or u.hostname not in LOOPBACK: raise SystemExit(f"RECUSADO: {label} deve apontar para loopback, veio {url!r}")
    @staticmethod
    def attack_id(prefix:str)->str:
        clean="".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in prefix)[:36]; return f"{clean}-{uuid.uuid4().hex[:12]}"
    def auth_agent(self):
        token=os.getenv("HERACLITUS_AGENT_TOKEN","").strip()
        if token: return {"Authorization":f"Bearer {token}"}
        basic=os.getenv("HERACLITUS_AGENT_BASIC","").strip()
        if basic: return {"Authorization":"Basic "+base64.b64encode(basic.encode()).decode()}
        return {}
    def core_auth(self,valid=True):
        if not valid: user,password="invalid-user","invalid-password"
        else:
            user=os.getenv("HERACLITUS_CORE_USERNAME","").strip(); password=os.getenv("HERACLITUS_CORE_PASSWORD","")
            if not user or not password: return {}
        return {"Authorization":"Basic "+base64.b64encode(f"{user}:{password}".encode()).decode()}
    def request(self,base,path,method="GET",body=None,headers=None,timeout=5.0,read_limit=2*1024*1024):
        self.assert_loopback_url(base,"request"); u=urlsplit(base); cls=http.client.HTTPSConnection if u.scheme=="https" else http.client.HTTPConnection
        conn=cls(u.hostname,u.port or (443 if u.scheme=="https" else 80),timeout=timeout); hdr={"User-Agent":"Agent-Atack-Heraclitus/3","Accept":"application/json"}
        if headers: hdr.update(headers)
        data=None
        if body is not None:
            data=bytes(body) if isinstance(body,(bytes,bytearray)) else (body.encode() if isinstance(body,str) else json.dumps(body,separators=(",",":"),ensure_ascii=False).encode())
            hdr.setdefault("Content-Type","application/json"); hdr.setdefault("Content-Length",str(len(data)))
        started=time.perf_counter()
        try:
            conn.request(method,(u.path.rstrip("/")+path) or "/",body=data,headers=hdr); resp=conn.getresponse(); raw=resp.read(read_limit); parsed=None
            if raw:
                try: parsed=json.loads(raw)
                except Exception: parsed=raw[:1000].decode("utf-8","replace")
            return resp.status,parsed,(time.perf_counter()-started)*1000
        except Exception as exc: return None,{"exception":type(exc).__name__,"detail":str(exc)[:200]},(time.perf_counter()-started)*1000
        finally: conn.close()
    def raw_http(self,base,wire,timeout=2.0,read_limit=65536):
        self.assert_loopback_url(base,"raw_http"); u=urlsplit(base); started=time.perf_counter(); out=bytearray()
        with socket.create_connection((u.hostname or "127.0.0.1",u.port or 80),timeout=timeout) as sock:
            sock.settimeout(timeout); sock.sendall(wire)
            while len(out)<read_limit:
                try: chunk=sock.recv(min(8192,read_limit-len(out)))
                except socket.timeout: break
                if not chunk: break
                out.extend(chunk)
        return bytes(out),(time.perf_counter()-started)*1000
    def close_partial(self,base,wire,delay=0.05):
        self.assert_loopback_url(base,"partial_http"); u=urlsplit(base); started=time.perf_counter()
        with socket.create_connection((u.hostname or "127.0.0.1",u.port or 80),timeout=2) as sock: sock.sendall(wire); time.sleep(max(0.0,min(delay,0.5)))
        return (time.perf_counter()-started)*1000
    def hits(self):
        url=self.cfg.get("upstream_hits")
        if not url: return None
        u=urlsplit(str(url)); root=f"{u.scheme}://{u.hostname}:{u.port or 80}"; s,b,_=self.request(root,u.path or "/hits")
        try: return int(b.get("hits",0)) if s==200 and isinstance(b,dict) else None
        except Exception: return None
    def mcp_headers(self,agent_id,run_id=None,method="tools/call"):
        h={"Content-Type":"application/json","mcp-method":method,"X-Heraclitus-Agent":agent_id,"X-Heraclitus-Run":run_id or self.campaign,"X-Heraclitus-User":"sandbox-operator","X-Heraclitus-Server":"safe-stub","X-Heraclitus-Environment":"lab"}; h.update(self.auth_agent()); return h
    @staticmethod
    def tool(request_id,name,args): return {"jsonrpc":"2.0","id":request_id,"method":"tools/call","params":{"name":name,"arguments":args}}
    @staticmethod
    def reason(body):
        try: return str(body["error"]["data"]["heraclitus"]["reason_code"])
        except Exception: return body.get("error") if isinstance(body,dict) and isinstance(body.get("error"),str) else None
    def native_evidence_seen(self,attack_id):
        base=self.cfg.get("agent_api")
        if not base: return None
        path=str(self.cfg.get("native_evidence_path") or "/api/v1/agent/tool-calls"); s,b,_=self.request(str(base),path,headers=self.auth_agent())
        if s!=200: return None
        return attack_id in json.dumps(b,ensure_ascii=False,sort_keys=True)
    def persist_redteam(self,result):
        if not self.cfg.get("agent_api"): return None
        self.sequence+=1; payload={"attack_id":result.attack_id,"campaign_id":self.campaign,"vector":result.vector,"target":result.target,"phase":"result","result":result.observed,"expected":result.expected,"blocked":result.blocked,"upstream_delta":result.upstream_delta,"transport_status":result.status,"sequence":self.sequence,"agent_id":result.agent_id,"category":result.category,"tags":result.tags}
        s,b,_=self.request(str(self.cfg["agent_api"]),"/api/v1/agent/red-team/events","POST",payload,self.auth_agent())
        if s in {200,201,202} and isinstance(b,dict):
            if isinstance(b.get("lsn"),int): return b["lsn"]
            if isinstance(b.get("integrity"),dict) and isinstance(b["integrity"].get("lsn"),int): return int(b["integrity"]["lsn"])
        return None
    def record(self,result,native_probe=True):
        result.evidence_lsn=self.persist_redteam(result)
        if native_probe: result.native_evidence=self.native_evidence_seen(result.attack_id)
        self.results.append(result); mark="PASS" if result.passed else "FAIL"; print(f"[{mark}] {result.category:11} {result.vector:34} status={str(result.status):>4} block={str(result.blocked):5} upΔ={result.upstream_delta} native={result.native_evidence} LSN={result.evidence_lsn}"); return result
    def health(self):
        if self.cfg.get("agent_api"):
            s,_,_=self.request(str(self.cfg["agent_api"]),"/api/v1/agent/status",headers=self.auth_agent())
            if s==200: return True
        if self.cfg.get("core_rest"):
            s,_,_=self.request(str(self.cfg["core_rest"]),"/stats",headers=self.core_auth(True)); return s==200
        return False

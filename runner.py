#!/usr/bin/env python3
"""Agent-Atack-Heraclitus v2.0.

Laboratório adversarial AUTORIZADO e *loopback-only* para HeraclitusDB.

A ferramenta não tem modo remoto, não executa shell e usa somente efeitos
sintéticos. O objetivo é qualificar autenticação, parsing, policy, approval,
isolamento de identidade, concorrência, replay e observabilidade do próprio
HeraclitusDB.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import http.client
import json
import os
import random
import socket
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

VERSION = "2.0.0"
LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}
MAX_AGENTS = 128
MAX_CONCURRENCY = 64
MAX_ITERATIONS = 100
MAX_OVERSIZED_BYTES = 8 * 1024 * 1024
MAX_REPORT_BODY = 2 * 1024 * 1024

PROFILES = {
    "smoke": {
        "agents": 4,
        "iterations": 1,
        "concurrency": 8,
        "suites": [
            "core_auth_tests",
            "grpc_reachability",
            "otlp_parser_matrix",
            "mcp_policy_basics",
            "jsonrpc_edge_matrix",
            "approval_flow",
            "path_traversal_matrix",
        ],
    },
    "full": {
        "agents": 12,
        "iterations": 3,
        "concurrency": 24,
        "suites": [
            "core_auth_tests",
            "grpc_reachability",
            "otlp_parser_matrix",
            "mcp_policy_basics",
            "jsonrpc_edge_matrix",
            "identity_isolation",
            "approval_flow",
            "approval_cross_agent",
            "approval_race",
            "mixed_concurrency",
            "multi_agent_swarm",
            "upstream_faults",
            "policy_invalid_reload",
            "path_traversal_matrix",
            "hostile_headers",
            "evidence_health_snapshot",
        ],
    },
    "massive": {
        "agents": 32,
        "iterations": 8,
        "concurrency": 48,
        "suites": [
            "core_auth_tests",
            "grpc_reachability",
            "otlp_parser_matrix",
            "mcp_policy_basics",
            "jsonrpc_edge_matrix",
            "identity_isolation",
            "approval_flow",
            "approval_cross_agent",
            "approval_race",
            "mixed_concurrency",
            "multi_agent_swarm",
            "upstream_faults",
            "policy_invalid_reload",
            "path_traversal_matrix",
            "hostile_headers",
            "evidence_health_snapshot",
        ],
    },
}

PERSONAS = (
    "malicious",
    "buggy-client",
    "replay-bot",
    "unicode-confusable",
    "identity-collision",
    "benign-control",
    "parser-fuzzer",
    "approval-abuser",
)


@dataclass
class Result:
    attack_id: str
    vector: str
    target: str
    expected: str
    result: str
    passed: bool
    status: int | None = None
    reason_code: str | None = None
    blocked: bool | None = None
    upstream_delta: int | None = None
    detail: str = ""
    duration_ms: float = 0.0
    evidence_lsn: int | None = None
    severity: str = "medium"
    agent_id: str | None = None
    tags: list[str] = field(default_factory=list)
    skipped: bool = False


class Lab:
    def __init__(self, cfg: dict, profile: str = "full", cli: argparse.Namespace | None = None):
        if profile not in PROFILES:
            raise SystemExit(f"perfil inválido: {profile}")
        self.cfg = dict(cfg)
        self.profile_name = profile
        self.profile = dict(PROFILES[profile])
        self.campaign = cfg.get("campaign") or f"sandbox-{int(time.time())}"
        self.seq = 0
        self.results: list[Result] = []
        self.random = random.Random(cfg.get("seed", 1337))

        for key in ["core_rest", "agent_api", "otlp", "mcp_gateway"]:
            self.assert_loopback_url(cfg[key], key)
        self.assert_loopback_url(
            cfg.get("upstream_hits", "http://127.0.0.1:19000/hits"),
            "upstream_hits",
        )
        host = cfg.get("core_grpc_host", "127.0.0.1")
        if host not in LOOPBACK:
            raise SystemExit(f"RECUSADO: core_grpc_host não é loopback: {host}")

        self.agent_count = self._bounded_int(
            getattr(cli, "agents", None) or cfg.get("agents") or self.profile["agents"],
            1,
            MAX_AGENTS,
            "agents",
        )
        self.iterations = self._bounded_int(
            getattr(cli, "iterations", None) or cfg.get("iterations") or self.profile["iterations"],
            1,
            MAX_ITERATIONS,
            "iterations",
        )
        self.concurrency = self._bounded_int(
            getattr(cli, "concurrency", None) or cfg.get("concurrency") or self.profile["concurrency"],
            1,
            MAX_CONCURRENCY,
            "concurrency",
        )
        oversized = int(cfg.get("oversized_bytes", 5 * 1024 * 1024))
        if not 1 <= oversized <= MAX_OVERSIZED_BYTES:
            raise SystemExit(
                f"RECUSADO: oversized_bytes deve ficar entre 1 e {MAX_OVERSIZED_BYTES}"
            )
        self.oversized_bytes = oversized

    @staticmethod
    def _bounded_int(value, low: int, high: int, name: str) -> int:
        try:
            n = int(value)
        except Exception as exc:
            raise SystemExit(f"RECUSADO: {name} inválido") from exc
        if not low <= n <= high:
            raise SystemExit(f"RECUSADO: {name} deve ficar entre {low} e {high}")
        return n

    @staticmethod
    def assert_loopback_url(url: str, label: str) -> None:
        u = urlsplit(url)
        if u.scheme not in {"http", "https"} or u.hostname not in LOOPBACK:
            raise SystemExit(f"RECUSADO: {label} deve apontar para loopback, veio {url!r}")

    def auth_agent(self) -> dict[str, str]:
        token = os.getenv("HERACLITUS_AGENT_TOKEN", "").strip()
        return {"Authorization": f"Bearer {token}"} if token else {}

    def core_auth(self, valid: bool = True) -> dict[str, str]:
        if not valid:
            user, password = "invalid-user", "invalid-password"
        else:
            user = os.getenv("HERACLITUS_CORE_USERNAME", "").strip()
            password = os.getenv("HERACLITUS_CORE_PASSWORD", "")
            if not user or not password:
                return {}
        raw = base64.b64encode(f"{user}:{password}".encode()).decode()
        return {"Authorization": f"Basic {raw}"}

    def request(
        self,
        base: str,
        path: str,
        method: str = "GET",
        body=None,
        headers: dict[str, str] | None = None,
        timeout: float = 8,
        read_body: bool = True,
        raw_json: bool = False,
    ):
        u = urlsplit(base)
        conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(u.hostname, u.port or (443 if u.scheme == "https" else 80), timeout=timeout)
        data = None
        h = {"User-Agent": f"Agent-Atack-Heraclitus/{VERSION}", "Accept": "application/json"}
        if headers:
            h.update(headers)
        if body is not None:
            if isinstance(body, (bytes, bytearray)):
                data = bytes(body)
            elif isinstance(body, str) and raw_json:
                data = body.encode("utf-8")
            else:
                data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
            h.setdefault("Content-Type", "application/json")
            h["Content-Length"] = str(len(data))
        started = time.perf_counter()
        try:
            conn.request(method, (u.path.rstrip("/") + path) or "/", body=data, headers=h)
            response = conn.getresponse()
            raw = response.read(MAX_REPORT_BODY if read_body else 0)
            parsed = None
            if raw:
                try:
                    parsed = json.loads(raw)
                except Exception:
                    parsed = raw[:500].decode("utf-8", "replace")
            return response.status, parsed, (time.perf_counter() - started) * 1000
        except Exception as exc:
            return None, {"exception": type(exc).__name__, "message": str(exc)[:160]}, (
                time.perf_counter() - started
            ) * 1000
        finally:
            conn.close()

    def upstream_stats(self) -> dict:
        base = self.cfg.get("upstream_hits", "http://127.0.0.1:19000/hits")
        u = urlsplit(base)
        root = f"{u.scheme}://{u.hostname}:{u.port or 80}"
        status, body, _ = self.request(root, "/stats")
        if status == 200 and isinstance(body, dict):
            return body
        status, body, _ = self.request(root, u.path or "/hits")
        if status == 200 and isinstance(body, dict):
            return {"hits": int(body.get("hits", 0)), "by_tool": {}, "by_method": {}}
        return {"hits": None, "by_tool": {}, "by_method": {}}

    @staticmethod
    def _counter(stats: dict, section: str, key: str) -> int | None:
        try:
            return int(stats.get(section, {}).get(key, 0))
        except Exception:
            return None

    def hits(self) -> int | None:
        value = self.upstream_stats().get("hits")
        return int(value) if isinstance(value, int) else None

    def tool_hits(self, tool: str) -> int | None:
        return self._counter(self.upstream_stats(), "by_tool", tool)

    def method_hits(self, method: str) -> int | None:
        return self._counter(self.upstream_stats(), "by_method", method)

    def report(self, result: Result) -> None:
        self.results.append(result)
        self.seq += 1
        payload = {
            "attack_id": result.attack_id,
            "campaign_id": self.campaign,
            "vector": result.vector,
            "target": result.target,
            "phase": "result",
            "result": result.result,
            "expected": result.expected,
            "reason_code": result.reason_code,
            "blocked": result.blocked,
            "upstream_delta": result.upstream_delta,
            "transport_status": result.status,
            "sequence": self.seq,
        }
        status, body, _ = self.request(
            self.cfg["agent_api"],
            "/api/v1/agent/red-team/events",
            "POST",
            payload,
            self.auth_agent(),
        )
        if status == 200 and isinstance(body, dict) and isinstance(body.get("lsn"), int):
            result.evidence_lsn = body["lsn"]
        mark = "SKIP" if result.skipped else ("PASS" if result.passed else "FAIL")
        print(
            f"[{mark}] {result.vector:31} status={str(result.status):>4} "
            f"blocked={str(result.blocked):5} upstreamΔ={result.upstream_delta} "
            f"LSN={result.evidence_lsn} {result.detail}"
        )

    def attack_id(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:10]}"

    @staticmethod
    def reason(body) -> str | None:
        try:
            return body["error"]["data"]["heraclitus"]["reason_code"]
        except Exception:
            if isinstance(body, dict) and isinstance(body.get("error"), str):
                return body["error"]
            return None

    def mcp_headers(self, agent: str = "redteam-agent", run: str | None = None, method: str = "tools/call"):
        h = {
            "Content-Type": "application/json",
            "mcp-method": method,
            "X-Heraclitus-Agent": agent,
            "X-Heraclitus-Run": run or f"redteam-{self.campaign}",
            "X-Heraclitus-User": "sandbox-operator",
            "X-Heraclitus-Server": "safe-stub",
            "X-Heraclitus-Environment": "lab",
        }
        h.update(self.auth_agent())
        return h

    @staticmethod
    def tool(request_id: str, name: str, args: dict) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        }

    def core_auth_tests(self):
        for label, headers, expect in [
            ("core-no-auth", {}, 401),
            ("core-bad-auth", self.core_auth(False), 401),
        ]:
            aid = self.attack_id(label)
            status, body, ms = self.request(self.cfg["core_rest"], "/stats", headers=headers)
            self.report(
                Result(
                    aid,
                    label,
                    "core:/stats",
                    f"HTTP {expect}",
                    f"HTTP {status}",
                    status == expect,
                    status=status,
                    blocked=status in {401, 403},
                    duration_ms=ms,
                    severity="high",
                    tags=["auth", "core"],
                )
            )
        good = self.core_auth(True)
        if good:
            aid = self.attack_id("core-valid-auth")
            status, body, ms = self.request(self.cfg["core_rest"], "/stats", headers=good)
            self.report(
                Result(
                    aid,
                    "core-valid-auth",
                    "core:/stats",
                    "HTTP 200",
                    f"HTTP {status}",
                    status == 200,
                    status=status,
                    blocked=False,
                    duration_ms=ms,
                    severity="low",
                    tags=["auth", "control"],
                )
            )

    def grpc_reachability(self):
        aid = self.attack_id("grpc-surface")
        host = self.cfg.get("core_grpc_host", "127.0.0.1")
        port = int(self.cfg.get("core_grpc_port", 17474))
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=2):
                reachable = True
        except OSError:
            reachable = False
        ms = (time.perf_counter() - started) * 1000
        self.report(
            Result(
                aid,
                "grpc-reachability",
                f"{host}:{port}",
                "surface measured",
                "reachable" if reachable else "closed",
                True,
                blocked=False,
                detail="reachability nao equivale a utorizacao gRPC",
                duration_ms=ms,
                severity="info",
                tags=["grpc", "surface"],
            )
       )

    def otlp_parser_matrix(self):
        cases = [
            ("malformed", b"{nao-e-json", "application/json", {400}),
            ("invalid-utf8", b"\xff\xfe\xfd", "application/json", {400}),
            ("bom-json", b"\xef\xbb\xbf{\"resourceSpans\":[]}", "application/json", {200, 400}),
            ("charset-json", b'{"resourceSpans":[]}', "application/json; charset=utf-8", {200}),
        ]
        for name, raw, content_type, accepted in cases:
            aid = self.attack_id(f"otlp-{name}")
            status, body, ms = self.request(
                self.cfg["otlp"],
                "/v1/traces",
                "POST",
                raw,
                {"Content-Type": content_type},
            )
            health_status, _, _ = self.request(
                self.cfg["otlp"],
                "/v1/traces",
                "POST",
                {"resourceSpans": []},
                {"Content-Type": "application/json"},
            )
            ok = status in accepted and health_status == 200
            self.report(
                Result(
                    aid,
                    f"otlp-{name}",
                    "otlp:/v1/traces",
                    f"status in {sorted(accepted)} and listener alive",
                    f"{status}, health={health_status}",
                    ok,
                    status=status,
                    blocked=status in {400, 413, 415, 422},
                    duration_ms=ms,
                    severity="medium",
                    tags=["otlp", "parser"],
                )
            )

        aid = self.attack_id("otlp-oversized")
        body = b'{"resourceSpans":[],"pad":"' + b"x" * self.oversized_bytes + b'"}'
        status, parsed, ms = self.request(
            self.cfg["otlp"],
            "/v1/traces",
            "POST",
            body,
            {"Content-Type": "application/json"},
            timeout=15,
        )
        self.report(
            Result(
                aid,
                "otlp-oversized",
                "otlp:/v1/traces",
                "HTTP 413",
                f"HTTP {status}",
                status == 413,
                status=status,
                reason_code=self.reason(parsed),
                blocked=status == 413,
                detail=f"{len(body)} bytes",
                duration_ms=ms,
                severity="high",
                tags=["otlp", "resource-limit"],
            )
        )

    def mcp_policy_basics(self):
        aid = self.attack_id("mcp-deny")
        before = self.tool_hits("exec")
        req = self.tool(
            aid,
            "exec",
            {"command": "echo HERACLITUS_REDTEAM_SHOULD_NOT_EXECUTE", "note": "synthetic deny probe"},
        )
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", req, self.mcp_headers()
       )
        after = self.tool_hits("exec")
        delta = after - before if before is not None and after is not None else None
        ok = status == 403 and delta in {0, None}
        self.report(
            Result(
                aid,
                "mcp-policy-deny",
                "mcp:exec",
                "403 and exec upstreamΔ=0",
                f"HTTP {status}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=status == 403,
                upstream_delta=delta,
                duration_ms=ms,
                severity="critical",
                tags=["mcp", "policy", "deny"],
            )
       )

        aid = self.attack_id("mcp-allow")
        before = self.tool_hits("lookup_vendor")
        req = self.tool(aid, "lookup_vendor", {"vendor": "synthetic-acme"})
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", req, self.mcp_headers()
        )
        after = self.tool_hits("lookup_vendor")
        delta = after - before if before is not None and after is not None else None
        ok = status == 200 and delta in {1, None}
        self.report(
            Result(
                aid,
                "mcp-benign-allow",
                "mcp:lookup_vendor",
                "200 and lookup upstreamΔ=1",
                f"HTTP {status}",
                ok,
                status=status,
                blocked=False,
                upstream_delta=delta,
                duration_ms=ms,
                severity="low",
                tags=["mcp", "control"],
            )
        )

    def jsonrpc_edge_matrix(self):
        aid = self.attack_id("mcp-batch")
        before_exec = self.tool_hits("exec")
        batch = [
            self.tool(aid + "a", "lookup_vendor", {"vendor": "batch-control"}),
            self.tool(aid + "b", "exec", {"command": "echo SAFE_MARKER"}),
        ]
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", batch, self.mcp_headers()
        )
        after_exec = self.tool_hits("exec")
        delta_exec = (
            after_exec - before_exec if before_exec is not None and after_exec is not None else None
        )
        ok = delta_exec in {0, None} and status not in {500, 502, 503}
        self.report(
            Result(
                aid,
                "jsonrpc-batch-bypass",
                "mcp:batch",
                "exec upstream_delta=0",
                f"HTTP {status}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=status in {400, 403, 405, 413, 422},
                upstream_delta=delta_exec,
                detail="mixed allow+deny batch",
                duration_ms=ms,
                severity="critical",
                tags=["mcp", "jsonrpc", "batch"],
            )
        )

        for label, tool_name in [
            ("unicode-confusable", "﵅��xec"),
            ("case-variant", "EXEC"),
            ("whitespace-tool", " exec "),
        ]:
            aid = self.attack_id(label)
            before = self.tool_hits(tool_name)
            req = self.tool(aid, tool_name, {"command": "echo SAFE_MARKER"})
            status, body, ms = self.request(
                self.cfg["mcp_gateway"], "/mcp", "POST", req, self.mcp_headers()
            )
            after = self.tool_hits(tool_name)
            delta = after - before if before is not None and after is not None else None
            ok = status != 200 and delta in {0, None}
            self.report(
                Result(
                    aid,
                    f"jsonrpc-{label}",
                    f"mcp:{tool_name}",
                    "default deny / no upstream",
                    f"HTTP {status}",
                    ok,
                    status=status,
                    reason_code=self.reason(body),
                    blocked=status in {400, 401, 403, 405, 422},
                    upstream_delta=delta,
                    duration_ms=ms,
                    severity="high",
                    tags=["mcp", "canonicalization"],
                )
            )

        aid = self.attack_id("duplicate-json-key")
        before_exec = self.tool_hits("exec")
        raw = (
            '{"jsonrpc":"2.0","id":"%s","method":"tools/call",'
            '"params":{"name":"exec","name":"lookup_vendor",'
            "arguments":{"vendor":"dup-key-control"}}}' % aid
        )
        status, body, ms = self.request(
            self.cfg["mcp_gateway"],
            "/mcp",
            "POST",
            raw,
            self.mcp_headers(),
            raw_json=True,
        )
        after_exec = self.tool_hits("exec")
        delta_exec = (
            after_exec - before_exec if before_exec is not None and after_exec is not None else None
        )
        ok = delta_exec in {0, None}
        self.report(
            Result(
                aid,
                "jsonrpc-duplicate-key",
                "mcp:parser",
                "no parser differential exposing exec",
                f"HTTP {status}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=status in {400, 403, 422},
                upstream_delta=delta_exec,
                duration_ms=ms,
                severity="high",
                tags=["mcp", "parser", "duplicate-key"],
            )
        )

        for method in ["resources/read", "prompts/get"]:
            aid = self.attack_id(method.replace("/", "-"))
            before = self.method_hits(method)
            req = {"jsonrpc": "2.0", "id": aid, "method": method, "params": {"uri": "lab://synthetic"}}
            headers = self.mcp_headers(method=method)
            status, body, ms = self.request(
                self.cfg["mcp_gateway"], "/mcp", "POST", req, headers
            )
            after = self.method_hits(method)
            delta = after - before if before is not None and after is not None else None
            self.report(
                Result(
                    aid,
                    f"protocol-{method}",
                    f"mcp:{method}",
                    "behavior measured and evidence correlated",
                    f"HTTP {status}",
                    True,
                    status=status,
                    reason_code=self.reason(body),
                    blocked=status in {401, 403},
                    upstream_delta=delta,
                    detail="informational protocol-surface probe",
                    duration_ms=ms,
                    severity="info",
                    tags=["mcp", "protocol-surface"],
                )
            )

    def identity_isolation(self):
        shared_id = self.attack_id("shared-jsonrpc-id")
        before = self.tool_hits("exec")
        statuses = []
        for agent in ["redteam-alpha", "redteam-beta"]:
            req = self.tool(shared_id, "exec", {"command": "echo SAFE_MARKER", "agent": agent})
            status, body, ms = self.request(
                self.cfg["mcp_gateway"],
                "/mcp",
                "POST",
                req,
                self.mcp_headers(agent=agent, run=f"{self.campaign}-{agent}"),
            )
            statuses.append(status)
        after = self.tool_hits("exec")
        delta = after - before if before is not None and after is not None else None
        ok = all(s == 403 for s in statuses) and delta in {0, None}
        self.report(
            Result(
                shared_id,
                "cross-agent-id-collision",
                "mcp:identity",
                "both agents denied, exec upstreamΔ=0",
                f"statuses={statuses}",
                ok,
                status=403 if statuses and all(s == 403 for s in statuses) else None,
                blocked=ok,
                upstream_delta=delta,
                severity="high",
                tags=["identity", "dedupe", "isolation"],
            )
        )

        aid = self.attack_id("missing-agent")
        before = self.tool_hits("exec")
        headers = self.mcp_headers()
        headers.pop("X-Heraclitus-Agent", None)
        status, body, ms = self.request(
            self.cfg["mcp_gateway"],
            "/mcp",
            "POST",
            self.tool(aid, "exec", {"command": "echo SAFE_MARKER"}),
            headers,
        )
        after = self.tool_hits("exec")
        delta = after - before if before is not None and after is not None else None
        ok = status != 200 and delta in {0, None}
        self.report(
            Result(
                aid,
                "missing-agent-identity",
                "mcp:identity",
                "fail closed",
                f"HTTP {status}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=status in {400, 401, 403, 422},
                upstream_delta=delta,
                duration_ms=ms,
                severity="critical",
                tags=["identity", "fail-closed"],
            )
       )

    def _request_approval(self, aid: str, agent: str, amount: int = 75000):
        req = self.tool(aid, "send_payment", {"amount": amount, "account": "synthetic-only"})
        status, body, ms = self.request(
            self.cfg["mcp_gateway"],
            "/mcp",
            "POST",
            req,
            self.mcp_headers(agent=agent, run=f"{self.campaign}-{agent}"),
       )
        approval = None
        try:
            approval = body["error"]["data"]["heraclitus"]["approval_id"]
        except Exception:
            pass
        return req, status, body, approval, ms

    def approval_flow(self):
        aid = self.attack_id("approval")
        agent = "redteam-approval-owner"
        req, status, body, approval, ms = self._request_approval(aid, agent)
        if status != 202 or not approval:
            self.report(
                Result(
                    aid,
                    "approval-single-use",
                    "mcp:send_payment",
                    "202 approval pending",
                    f"HTTP {status}",
                    False,
                    status=status,
                    reason_code=self.reason(body),
                    blocked=True,
                    detail="policy não abriu approval",
                    severity="high",
                    tags=["approval"],
                )
            )
            return
        approve_status, _, _ = self.request(
            self.cfg["agent_api"],
            f"/api/v1/agent/approvals/{approval}/approve",
            "POST",
            {},
            self.auth_agent(),
        )
        before1 = self.tool_hits("send_payment")
        status1, body1, _ = self.request(
            self.cfg["mcp_gateway"],
            "/mcp",
            "POST",
            req,
            self.mcp_headers(agent=agent, run=f"{self.campaign}-{agent}"),
        )
        after1 = self.tool_hits("send_payment")
        delta1 = after1 - before1 if before1 is not None and after1 is not None else None
        before2 = self.tool_hits("send_payment")
        status2, body2, _ = self.request(
            self.cfg["mcp_gateway"],
            "/mcp",
            "POST",
            req,
            self.mcp_headers(agent=agent, run=f"{self.campaign}-{agent}"),
        )
        after2 = self.tool_hits("send_payment")
        delta2 = after2 - before2 if before2 is not None and after2 is not None else None
        ok = (
            approve_status == 200
            and status1 == 200
            and delta1 in {1, None}
            and status2 != 200
            and delta2 in {0, None}
        )
        self.report(
            Result(
                aid,
                "approval-single-use",
                "mcp:send_payment",
                "pending→approve→execute once→replay deny",
                f"{status}/{approve_status}/{status1}/{status2}",
                ok,
                status=status2,
                reason_code=self.reason(body2),
                blocked=status2 != 200,
                upstream_delta=(delta1 or 0) + (delta2 or 0),
                detail=f"approval={approval[:18]}...",
                duration_ms=ms,
                severity="critical",
                agent_id=agent,
                tags=["approval", "replay", "single-use"],
            )
        )

    def approval_cross_agent(self):
        aid = self.attack_id("approval-cross-agent")
        owner = "redteam-approval-alpha"
        attacker = "redteam-approval-beta"
        req, status, body, approval, _ = self._request_approval(aid, owner)
        if status != 202 or not approval:
            self.report(
                Result(
                    aid,
                    "approval-cross-agent",
                    "mcp:send_payment",
                    "approval available",
                    f"HTTP {status}",
                    False,
                    status=status,
                    blocked=True,
                    detail="approval unavailable",
                    severity="high",
                )
            )
            return
        approve_status, _, _ = self.request(
            self.cfg["agent_api"],
            f"/api/v1/agent/approvals/{approval}/approve",
            "POST",
            {},
            self.auth_agent(),
        )
        before = self.tool_hits("send_payment")
        status2, body2, ms = self.request(
            self.cfg["mcp_gateway"],
            "/mcp",
            "POST",
            req,
            self.mcp_headers(agent=attacker, run=f"{self.campaign}-{attacker}"),
        )
        after = self.tool_hits("send_payment")
        delta = after - before if before is not None and after is not None else None
        ok = approve_status == 200 and status2 != 200 and delta in {0, None}
        self.report(
            Result(
                aid,
                "approval-cross-agent",
                "mcp:send_payment",
                "approval bound to original agent",
                f"HTTP {status2}",
                ok,
                status=status2,
                reason_code=self.reason(body2),
                blocked=status2 != 200,
                upstream_delta=delta,
                duration_ms=ms,
                severity="critical",
                agent_id=attacker,
                tags=["approval", "identity", "binding"],
            )
        )

    def approval_race(self):
        aid = self.attack_id("approval-race")
        agent = "redteam-race"
        req, status, body, approval, _ = self._request_approval(aid, agent)
        if status != 202 or not approval:
            self.report(
                Result(
                    aid,
                    "approval-race",
                    "mcp:send_payment",
                    "approval available",
                    f"HTTP {status}",
                    False,
                    status=status,
                    blocked=True,
                    severity="high",
                )
            )
            return
        approve_status, _, _ = self.request(
            self.cfg["agent_api"],
            f"/api/v1/agent/approvals/{approval}/approve",
            "POST",
            {},
            self.auth_agent(),
        )
        racers = min(self.concurrency, int(self.cfg.get("approval_racers", 16)))
        before = self.tool_hits("send_payment")
        started = time.perf_counter()

        def one(_):
            return self.request(
                self.cfg["mcp_gateway"],
                "/mcp",
                "POST",
                req,
                self.mcp_headers(agent=agent, run=f"{self.campaign}-{agent}"),
                timeout=10,
            )[0]

        with concurrent.futures.ThreadPoolExecutor(max_workers=racers) as executor:
            statuses = list(executor.map(one, range(racers)))
        after = self.tool_hits("send_payment")
        delta = after - before if before is not None and after is not None else None
        successes = sum(s == 200 for s in statuses)
        ok = approve_status == 200 and successes == 1 and delta in {1, None}
        self.report(
            Result(
                aid,
                "approval-consume-race",
                "mcp:send_payment",
                "exactly one execution",
                f"200={successes}/{racers}",
                ok,
                status=200 if successes == 1 else None,
                blocked=ok,
                upstream_delta=delta,
                detail=f"{(time.perf_counter()-started)*1000:.0f}ms total",
                severity="critical",
                agent_id=agent,
                tags=["approval", "race", "concurrency"],
            )
        )

    def mixed_concurrency(self):
        aid = self.attack_id("mixed-concurrency")
        n = max(8, min(self.concurrency, 48))
        before_exec = self.tool_hits("exec")
        before_lookup = self.tool_hits("lookup_vendor")

        def one(i):
            if i % 2 == 0:
                tool_name = "exec"
                args = {"command": "echo SAFE_MARKER", "i": i}
            else:
                tool_name = "lookup_vendor"
                args = {"vendor": f"mixed-{i"}
            req = self.tool(f"{aid}-{i}", tool_name, args)
            return tool_name, self.request(
                self.cfg["mcp_gateway"],
                "/mcp",
                "POST",
                req,
                self.mcp_headers(agent=f"mixed-agent-{i%4}", run=f"{aid}-run"),
                timeout=10,
            )[0]

        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as executor:
            rows = list(executor.map(one, range(n)))
        after_exec = self.tool_hits("exec")
        after_lookup = self.tool_hits("lookup_vendor")
        exec_delta = (
            after_exec - before_exec if before_exec is not None and after_exec is not None else None
        )
        lookup_delta = (
            after_lookup - before_lookup
            if before_lookup is not None and after_lookup is not None
            else None
        )
        denied_exec = sum(tool == "exec" and status == 403 for tool, status in rows)
        allowed_lookup = sum(tool == "lookup_vendor" and status == 200 for tool, status in rows)
        expected_each = n // 2
        ok = (
            denied_exec == expected_each
            and allowed_lookup == expected_each
            and exec_delta in {0, None}
            and lookup_delta in {expected_each, None}
        )
        self.report(
            Result(
                aid,
                "mixed-allow-deny-concurrency",
                "mcp:gateway",
                "no cross-talk between allow and deny",
                f"deny={denied_exec}, allow={allowed_lookup}",
                ok,
                status=200 if ok else None,
                blocked=ok,
                upstream_delta=exec_delta,
                detail=f"lookupΔ={lookup_delta}",
                severity="critical",
                tags=["concurrency", "policy", "isolation"],
            )
       )

    def multi_agent_swarm(self):
        aid = self.attack_id("swarm")
        before_exec = self.tool_hits("exec")
        before_lookup = self.tool_hits("lookup_vendor")
        tasks = []
        for agent_index in range(self.agent_count):
            persona = PERSONAS[agent_index % len(PERSONAS)]
            for iteration in range(self.iterations):
                tasks.append((agent_index, persona, iteration))
        self.random.shuffle(tasks)

        def one(item):
            agent_index, persona, iteration = item
            agent = f"swarm-{agent_index:03d}-{persona}"
            rid = f"{aid}-{agent_index}-{iteration}"
            headers = self.mcp_headers(agent=agent, run=f"{self.campaign}-swarm-{agent_index}")
            if persona == "benign-control":
                req = self.tool(rid, "lookup_vendor", {"vendor": f"swarm-{agent_index}"})
                expected = "allow"
            elif persona == "buggy-client":
                req = {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {}}
                expected = "block"
            elif persona == "unicode-confusable":
                req = self.tool(rid, "﵅��xec", {"command": "echo SAFE_MARKER"})
                expected = "block"
            elif persona == "parser-fuzzer":
                headers["Content-Type"] = "text/plain"
                req = self.tool(rid, "exec", {"command": "echo SAFE_MARKER"})
                expected = "block"
            elif persona == "identity-collision":
                req = self.tool("shared-swarm-id", "exec", {"command": "echo SAFE_MARKER"})
                expected = "block"
            elif persona == "replay-bot":
                req = self.tool(rid, "exec", {"command": "echo SAFE_MARKER"})
                s1 = self.request(self.cfg["mcp_gateway"], "/mcp", "POST", req, headers, timeout=10)[0]
                s2 = self.request(self.cfg["mcp_gateway"], "/mcp", "POST", req, headers, timeout=10)[0]
                return persona, "block", [s1, s2]
            elif persona == "approval-abuser":
                req = self.tool(rid, "send_payment", {"amount": 90000, "account": "synthetic-swarm"})
                expected = "pending"
            else:
                req = self.tool(rid, "exec", {"command": "echo SAFE_MARKER"})
                expected = "block"
            status = self.request(
                self.cfg["mcp_gateway"], "/mcp", "POST", req, headers, timeout=10
            )[0]
            return persona, expected, [status]

        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            rows = list(executor.map(one, tasks))
        elapsed = (time.perf_counter() - started) * 1000
        after_exec = self.tool_hits("exec")
        after_lookup = self.tool_hits("lookup_vendor")
        exec_delta = (
            after_exec - before_exec if before_exec is not None and after_exec is not None else None
        )
        lookup_delta = (
            after_lookup - before_lookup
            if before_lookup is not None and after_lookup is not None
            else None
        )
        failures = 0
        allows = 0
        pending = 0
        blocks = 0
        for persona, expected, statuses in rows:
            if expected == "allow":
                good = all(s == 200 for s in statuses)
                allows += int(good)
            elif expected == "pending":
                good = all(s == 202 for s in statuses)
                pending += int(good)
            else:
                good = all(s in {400, 401, 403, 405, 413, 415, 422, 431} for s in statuses)
                blocks += int(good)
            failures += int(not good)
        ok = failures == 0 and exec_delta in {0, None}
        self.report(
            Result(
                aid,
                "multi-agent-adversarial-swarm",
                "mcp:gateway",
                "all personas isolated; exec upstreamΔ=0",
                f"tasks={len(tasks)}, failures={failures}",
                ok,
                status=200 if ok else None,
                blocked=ok,
                upstream_delta=exec_delta,
                detail=(
                    f"agents={self.agent_count} iterations={self.iterations} "
                    f"block={blocks} allow={allows} pending={pending} lookupΔ={lookup_delta} "
                    f"{elapsed:.0f}ms"
                ),
                severity="critical",
                tags=["multi-agent", "swarm", "concurrency"],
            )
        )

    def upstream_faults(self):
        for vendor, label, expect_status in [
            ("__stub_500__", "upstream-500", 500),
            ("__stub_delay__", "upstream-delay", 200),
            ("__stub_large__", "upstream-large-response", 200),
        ]:
            aid = self.attack_id(label)
            before = self.tool_hits("lookup_vendor")
            req = self.tool(aid, "lookup_vendor", {"vendor": vendor})
            status, body, ms = self.request(
                self.cfg["mcp_gateway"],
                "/mcp",
                "POST",
                req,
                self.mcp_headers(agent=f"redteam-{label}"),
                timeout=10,
            )
            health, _, _ = self.request(
                self.cfg["agent_api"], "/api/v1/agent/status", headers=self.auth_agent()
            )
            after = self.tool_hits("lookup_vendor")
            delta = after - before if before is not None and after is not None else None
            ok = health == 200 and status is not None and delta in {1, None}
            self.report(
                Result(
                    aid,
                    label,
                    "mcp:upstream",
                    f"fault observed; gateway remains healthy",
                    f"HTTP {status}, health={health}",
                    ok,
                    status=status,
                    blocked=False,
                    upstream_delta=delta,
                    detail=f"expected stub={expect_status}, duration={ms:.0f}ms",
                    duration_ms=ms,
                    severity="medium",
                    tags=["upstream", "resilience"],
                )
            )

    def policy_invalid_reload(self):
        aid = self.attack_id("policy-invalid")
        status0, body0, _ = self.request(
            self.cfg["agent_api"], "/api/v1/agent/policies", headers=self.auth_agent()
        )
        before = json.dumps(body0, sort_keys=True) if status0 == 200 else None
        status_invalid, body_invalid, ms = self.request(
            self.cfg["agent_api"],
            "/api/v1/agent/policies/activate",
            "POST",
            {"document": 'version: "agent-policy-v999"\n'},
            self.auth_agent(),
        )
        status1, body1, _ = self.request(
            self.cfg["agent_api"], "/api/v1/agent/policies", headers=self.auth_agent()
        )
        after = json.dumps(body1, sort_keys=True) if status1 == 200 else None
        ok = status_invalid in {400, 401, 403, 422} and (before is None or after == before)
        self.report(
            Result(
                aid,
                "invalid-policy-reload",
                "agent:policies",
                "invalid policy cannot replace active",
                f"HTTP {status_invalid}",
                ok,
                status=status_invalid,
                reason_code=self.reason(body_invalid),
                blocked=ok,
                detail="active snapshot unchanged" if before is not None and after == before else "snapshot unavailable",
                duration_ms=ms,
                severity="critical",
                tags=["policy", "reload", "fail-closed"],
            )
       )

    def path_traversal_matrix(self):
        paths = [
            "/api/v1/agent/bundles/%2e%2e/%2e%2e/etc/passwd",
            "/api/v1/agent/bundles/..%2f..%2fetc%2fpasswd",
            "/api/v1/agent/bundles/%252e%252e%252fetc%252fpasswd",
        ]
        for i, path in enumerate(paths):
            aid = self.attack_id(f"path-traversal-{i}")
            status, body, ms = self.request(
                self.cfg["agent_api"], path, headers=self.auth_agent(), read_body=False
            )
            ok = status != 200
            self.report(
                Result(
                    aid,
                    f"bundle-path-traversal-{i+1}",
                    "agent:bundle-download",
                    "not HTTP 200",
                    f"HTTP {status}",
                    ok,
                    status=status,
                    blocked=ok,
                    detail="response body intentionally not read",
                    duration_ms=ms,
                    severity="critical",
                    tags=["path-traversal", "bundle"],
                )
            )

    def hostile_headers(self):
        aid = self.attack_id("header-size")
        headers = self.mcp_headers()
        headers["X-Heraclitus-Agent"] = "A" * 16384
        req = self.tool(aid, "lookup_vendor", {"vendor": "header-test"})
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", req, headers
        )
        health_status, _, _ = self.request(
            self.cfg["agent_api"], "/api/v1/agent/status", headers=self.auth_agent()
       )
        ok = health_status == 200
        self.report(
            Result(
                aid,
                "oversized-identity-header",
                "mcp:headers",
                "service remains alive",
                f"HTTP {status}, health {health_status}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=status in {400, 413, 431},
                detail="16KiB identity header",
                duration_ms=ms,
                severity="high",
                tags=["headers", "resource-limit"],
            )
        )

    def evidence_health_snapshot(self):
        aid = self.attack_id("evidence-health")
        status, body, ms = self.request(
            self.cfg["agent_api"], "/api/v1/agent/status", headers=self.auth_agent()
        )
        text = json.dumps(body, sort_keys=True) if isinstance(body, dict) else str(body)
        lower = text.lower()
        unhealthy = "unhealthy" in lower or '"healthy': false' in lower
        ok = status == 200 and not unhealthy
        detail = text[:240]
        self.report(
            Result(
                aid,
                "evidence-health-snapshot",
                "agent:status",
                "HTTP 200 and evidence plane not unhealthy",
                f"HTTP {status}",
                ok,
                status=status,
                blocked=False,
                detail=detail,
                duration_ms=ms,
                severity="high",
                tags=["evidence", "health", "observability"],
            )
       )

    def run(self):
        print(
            f"Agent-Atack-Heraclitus v{VERSION} campaign={self.campaign} "
            f"profile={self.profile_name} LOOPBACK-ONLY agents={self.agent_count} "
            f"iterations={self.iterations} concurrency={self.concurrency}"
        )
        suites = [getattr(self, name) for name in self.profile["suites"]]
        for fn in suites:
            try:
                fn()
            except Exception as exc:
                aid = self.attack_id("runner-error")
                self.report(
                    Result(
                        aid,
                        fn.__name__,
                        "runner",
                        "no exception",
                        type(exc).__name__,
                        False,
                        detail=str(exc)[:240],
                        severity="high",
                        tags=["runner"],
                    )
                )
        return self.results


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def markdown_report(product: str, campaign: str, profile: str, results: list[Result]) -> str:
    passed = sum(r.passed for r in results if not r.skipped)
    failed = sum((not r.passed) for r in results if not r.skipped)
    skipped = sum(r.skipped for r in results)
    evidence = sum(r.evidence_lsn is not None for r in results)
    lines = [
        f"# {product} — relatório de campanha",
        "",
        f"- **Campaign:** `{campaign}`",
        f"- **Profile:** `{profile}`",
        f"- **PASS:** {passed}",
        f"- **FAIL:** {failed}",
        f"- **SKIP:** {skipped}",
        f"- **Eventos com LSN de red-team:** {evidence}/{len(results)}",
        "",
        "| Status | Severidade | Vetor | HTTP | Bloqueado | Upstream Δ | LSN |",
        "|---|---|---|---:|---|---:|---:|",
    ]
    for r in results:
        status = "SKIP" if r.skipped else ("PASS" if r.passed else "FAIL")
        lines.append(
            f"| {status} | {r.severity} | `{r.vector}` | {r.status if r.status is not None else '-'} | "
            f"{r.blocked if r.blocked is not None else '-'} | "
            f"{r.upstream_delta if r.upstream_delta is not None else '-'} | "
            f"{r.evidence_lsn if r.evidence_lsn is not None else '-'} |"
        )
    failures = [r for r in results if not r.passed and not r.skipped]
    if failures:
        lines += ["", "## Falhas que merecem investigação", ""]
        for r in failures:
            lines.append(f"- **{r.vector}**: esperado `{r.expected}`, observado `{r.result}`. {r.detail}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Authorized, loopback-only adversarial qualification for HeraclitusDB"
    )
    parser.add_argument("--config", default="config.example.json")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="full")
    parser.add_argument("--agents", type=int, default=None)
    parser.add_argument("--iterations", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--report", default=None)
    parser.add_argument("--markdown", default=None)
    args = parser.parse_args()

    cfg = load(args.config)
    lab = Lab(cfg, args.profile, args)
    results = lab.run()
    summary = {
        "total": len(results),
        "passed": sum(r.passed for r in results if not r.skipped),
        "failed": sum((not r.passed) for r in results if not r.skipped),
        "skipped": sum(r.skipped for r in results),
        "evidence_lsn": sum(r.evidence_lsn is not None for r in results),
    }
    out = {
        "product": "Agent-Atack-Heraclitus",
        "version": VERSION,
        "campaign": lab.campaign,
        "profile": args.profile,
        "generated_at": int(time.time()),
        "configuration": {
            "agents": lab.agent_count,
            "iterations": lab.iterations,
            "concurrency": lab.concurrency,
            "loopback_only": True,
        },
        "results": [asdict(x) for x in results],
        "summary": summary,
    }
    report = Path(args.report or f"reports/{lab.campaign}.json")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    md = Path(args.markdown or report.with_suffix(".md"))
    md.parent.mkdir(parents=True, exist_ok=True)
    md.write_text(
        markdown_report(out["product"], lab.campaign, args.profile, results), encoding="utf-8"
    )
    print(
        f"\nSUMMARY {summary['passed']}/{summary['total']} passed; "
        f"failed={summary['failed']} evidence_lsn={summary['evidence_lsn']}/{summary['total']} "
        f"json={report} markdown={md}"
    )
    return 0 if summary["failed"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())

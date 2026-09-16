#!/usr/bin/env python3
"""Agent-Atack-Heraclitus v3.0.

Camada avançada de qualificação adversarial sobre o runner v2.

Continua deliberadamente loopback-only. Os novos probes foram derivados de uma
auditoria recursiva do HeraclitusDB e procuram divergências entre parser/policy,
fronteiras de identidade, forwarding de headers, cobertura de métodos MCP e
limites de resposta do upstream. O stub continua sintético e não executa shell.
"""
from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from dataclasses import asdict
from pathlib import Path

import runner as base

VERSION = "3.0.0"

EXTRA_SUITES = {
    "smoke": [
        "mcp_header_body_differentials",
        "header_forwarding_boundaries",
    ],
    "full": [
        "mcp_header_body_differentials",
        "gateway_auth_boundary",
        "header_forwarding_boundaries",
        "protocol_data_methods_policy",
        "correlation_header_limits",
        "upstream_response_limit",
    ],
    "massive": [
        "mcp_header_body_differentials",
        "gateway_auth_boundary",
        "header_forwarding_boundaries",
        "protocol_data_methods_policy",
        "correlation_header_limits",
        "upstream_response_limit",
    ],
}


class AdvancedLab(base.Lab):
    """Runner v2 + probes encontrados na auditoria recursiva."""

    def latest_stub_call(self, request_id: str | None = None, tool: str | None = None):
        rows = self.upstream_stats().get("last", [])
        if not isinstance(rows, list):
            return None
        for row in reversed(rows):
            if not isinstance(row, dict):
                continue
            if request_id is not None and str(row.get("id")) != request_id:
                continue
            if tool is not None and row.get("tool") != tool:
                continue
            return row
        return None

    def _exec_delta(self, before: int | None) -> int | None:
        after = self.tool_hits("exec")
        return after - before if before is not None and after is not None else None

    def _lookup_delta(self, before: int | None) -> int | None:
        after = self.tool_hits("lookup_vendor")
        return after - before if before is not None and after is not None else None

    def mcp_header_body_differentials(self):
        # 1) O header diz ping, o corpo pede tools/call/exec. A autoridade deve
        # ser o corpo canônico ou a divergência deve ser recusada. Nunca forward.
        aid = self.attack_id("header-method-mismatch")
        before = self.tool_hits("exec")
        headers = self.mcp_headers(method="ping")
        req = self.tool(aid, "exec", {"command": "echo SAFE_MARKER", "probe": "method-mismatch"})
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", req, headers, timeout=10
        )
        delta = self._exec_delta(before)
        ok = delta in {0, None}
        self.report(
            base.Result(
                aid,
                "mcp-header-body-method-mismatch",
                "mcp:parser/policy",
                "body exec cannot bypass via mcp-method header",
                f"HTTP {status}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=delta == 0,
                upstream_delta=delta,
                duration_ms=ms,
                severity="critical",
                tags=["mcp", "parser-differential", "header-body"],
            )
        )

        # 2) O header anuncia uma tool permitida, o corpo contém exec. Se a
        # policy olhar para o header e o upstream para o corpo, há TOCTOU lógico.
        aid = self.attack_id("header-name-mismatch")
        before = self.tool_hits("exec")
        headers = self.mcp_headers(method="tools/call")
        headers["mcp-name"] = "lookup_vendor"
        req = self.tool(aid, "exec", {"command": "echo SAFE_MARKER", "probe": "name-mismatch"})
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", req, headers, timeout=10
        )
        delta = self._exec_delta(before)
        ok = delta in {0, None}
        self.report(
            base.Result(
                aid,
                "mcp-header-body-tool-mismatch",
                "mcp:parser/policy",
                "header cannot relabel an exec body as an allowed tool",
                f"HTTP {status}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=delta == 0,
                upstream_delta=delta,
                duration_ms=ms,
                severity="critical",
                tags=["mcp", "policy", "parser-differential", "header-body"],
            )
        )

        # 3) BOM antes de JSON válido. Se o gateway e o upstream discordarem
        # sobre o que é JSON, o caminho seguro é rejeitar sem chegar ao exec.
        aid = self.attack_id("bom-parser-diff")
        before = self.tool_hits("exec")
        req = self.tool(aid, "exec", {"command": "echo SAFE_MARKER", "probe": "bom"})
        raw = b"\xef\xbb\xbf" + json.dumps(req, separators=(",", ":")).encode("utf-8")
        headers = self.mcp_headers()
        headers.pop("mcp-method", None)
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", raw, headers, timeout=10
        )
        delta = self._exec_delta(before)
        ok = delta in {0, None}
        self.report(
            base.Result(
                aid,
                "mcp-bom-parser-differential",
                "mcp:parser",
                "ambiguous JSON cannot reach exec",
                f"HTTP {status}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=delta == 0,
                upstream_delta=delta,
                duration_ms=ms,
                severity="critical",
                tags=["mcp", "parser-differential", "bom"],
            )
        )

        # 4) Corpo não-objeto. O Gateway não pode interpretar como não-tool e
        # encaminhar algo que o upstream entenda de forma privilegiada.
        for label, raw in [
            ("scalar-string", b'"tools/call"'),
            ("scalar-number", b"1"),
            ("null", b"null"),
        ]:
            aid = self.attack_id(f"jsonrpc-{label}")
            before = self.hits()
            headers = self.mcp_headers()
            headers.pop("mcp-method", None)
            status, body, ms = self.request(
                self.cfg["mcp_gateway"], "/mcp", "POST", raw, headers, timeout=10
            )
            after = self.hits()
            delta = after - before if before is not None and after is not None else None
            ok = delta in {0, None}
            self.report(
                base.Result(
                    aid,
                    f"jsonrpc-{label}-fail-closed",
                    "mcp:parser",
                    "non-object JSON rejected before upstream",
                    f"HTTP {status}",
                    ok,
                    status=status,
                    reason_code=self.reason(body),
                    blocked=delta == 0,
                    upstream_delta=delta,
                    duration_ms=ms,
                    severity="high",
                    tags=["mcp", "parser", "fail-closed"],
                )
            )

    def gateway_auth_boundary(self):
        # Só é um gate obrigatório se a própria Agent API disser que há
        # autenticação real. Em dev_local seria teatro exigir um resultado.
        status0, body0, _ = self.request(
            self.cfg["agent_api"], "/api/v1/agent/status", headers=self.auth_agent()
        )
        auth_mode = body0.get("auth") if status0 == 200 and isinstance(body0, dict) else None
        aid = self.attack_id("gateway-auth")
        if auth_mode not in {"basic", "oidc"}:
            self.report(
                base.Result(
                    aid,
                    "gateway-auth-boundary",
                    "mcp:identity",
                    "authenticated deployment only",
                    f"auth={auth_mode or 'unavailable'}",
                    True,
                    blocked=None,
                    detail="SKIP: Agent API não declarou basic/oidc",
                    severity="info",
                    tags=["identity", "auth"],
                    skipped=True,
                )
            )
            return

        before = self.tool_hits("lookup_vendor")
        headers = self.mcp_headers(agent="unauthenticated-v3")
        headers.pop("Authorization", None)
        req = self.tool(aid, "lookup_vendor", {"vendor": "auth-boundary-control"})
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", req, headers, timeout=10
        )
        delta = self._lookup_delta(before)
        ok = status in {401, 403} and delta in {0, None}
        self.report(
            base.Result(
                aid,
                "gateway-auth-boundary",
                "mcp:identity",
                "unauthenticated caller cannot invoke allowed tool",
                f"HTTP {status}, auth={auth_mode}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=ok,
                upstream_delta=delta,
                duration_ms=ms,
                severity="critical",
                tags=["identity", "auth", "gateway"],
            )
        )

    def header_forwarding_boundaries(self):
        # Authorization deve terminar na fronteira que o autentica. Usa um
        # sentinel sintético, nunca a credencial real do operador.
        aid = self.attack_id("auth-header-leak")
        before = self.tool_hits("lookup_vendor")
        headers = self.mcp_headers(agent="header-probe")
        headers["Authorization"] = "Bearer REDTEAM_SENTINEL_NOT_A_SECRET"
        req = self.tool(aid, "lookup_vendor", {"vendor": "header-auth-probe"})
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", req, headers, timeout=10
        )
        delta = self._lookup_delta(before)
        row = self.latest_stub_call(aid, "lookup_vendor")
        leaked = bool(row and row.get("headers", {}).get("authorization"))
        ok = not leaked
        self.report(
            base.Result(
                aid,
                "authorization-header-boundary",
                "mcp:upstream-headers",
                "Authorization never forwarded to MCP upstream",
                f"HTTP {status}, leaked={leaked}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=status in {401, 403},
                upstream_delta=delta,
                duration_ms=ms,
                severity="critical",
                tags=["headers", "credential-boundary", "upstream"],
            )
        )

        # RFC 9110: Connection pode nomear headers hop-by-hop adicionais. O
        # proxy precisa retirar o header nomeado, não só a lista estática.
        aid = self.attack_id("connection-hop")
        before = self.tool_hits("lookup_vendor")
        headers = self.mcp_headers(agent="hop-probe")
        headers["Connection"] = "X-Redteam-Hop"
        headers["X-Redteam-Hop"] = "synthetic-hop-sentinel"
        req = self.tool(aid, "lookup_vendor", {"vendor": "connection-hop-probe"})
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", req, headers, timeout=10
        )
        delta = self._lookup_delta(before)
        row = self.latest_stub_call(aid, "lookup_vendor")
        leaked = bool(row and row.get("headers", {}).get("x-redteam-hop"))
        ok = not leaked
        self.report(
            base.Result(
                aid,
                "connection-nominated-hop-header",
                "mcp:upstream-headers",
                "Connection-nominated header stripped",
                f"HTTP {status}, leaked={leaked}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=False,
                upstream_delta=delta,
                duration_ms=ms,
                severity="high",
                tags=["headers", "proxy", "hop-by-hop"],
            )
        )

        # Controle positivo: os headers internos x-heraclitus-* jamais devem
        # sair do gateway. Se a chamada não chegar ao stub, o teste é inconclusivo.
        aid = self.attack_id("correlation-strip")
        before = self.tool_hits("lookup_vendor")
        headers = self.mcp_headers(agent="private-agent-marker", run="private-run-marker")
        req = self.tool(aid, "lookup_vendor", {"vendor": "correlation-strip-control"})
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", req, headers, timeout=10
        )
        delta = self._lookup_delta(before)
        row = self.latest_stub_call(aid, "lookup_vendor")
        if row is None:
            self.report(
                base.Result(
                    aid,
                    "heraclitus-correlation-header-strip",
                    "mcp:upstream-headers",
                    "observable only when control call reaches stub",
                    f"HTTP {status}",
                    True,
                    status=status,
                    blocked=status in {401, 403},
                    upstream_delta=delta,
                    detail="SKIP: controle não chegou ao upstream",
                    severity="info",
                    tags=["headers", "privacy"],
                    skipped=True,
                )
            )
        else:
            hp = row.get("headers", {})
            leaked = bool(hp.get("x-heraclitus-agent") or hp.get("x-heraclitus-run"))
            self.report(
                base.Result(
                    aid,
                    "heraclitus-correlation-header-strip",
                    "mcp:upstream-headers",
                    "x-heraclitus-* stripped",
                    f"HTTP {status}, leaked={leaked}",
                    not leaked,
                    status=status,
                    blocked=False,
                    upstream_delta=delta,
                    duration_ms=ms,
                    severity="high",
                    tags=["headers", "privacy", "correlation"],
                )
            )

    def protocol_data_methods_policy(self):
        strict = bool(self.cfg.get("expect_data_methods_blocked", True))
        for method in ["resources/read", "prompts/get"]:
            aid = self.attack_id("data-method-" + method.replace("/", "-"))
            before = self.method_hits(method)
            req = {
                "jsonrpc": "2.0",
                "id": aid,
                "method": method,
                "params": {"uri": "lab://synthetic-sensitive-object"},
            }
            status, body, ms = self.request(
                self.cfg["mcp_gateway"],
                "/mcp",
                "POST",
                req,
                self.mcp_headers(agent="data-surface-probe", method=method),
                timeout=10,
            )
            after = self.method_hits(method)
            delta = after - before if before is not None and after is not None else None
            if strict:
                ok = status in {400, 401, 403, 405, 422} and delta in {0, None}
                expected = "data-bearing MCP method policy-gated / no upstream"
            else:
                ok = True
                expected = "behavior measured (strict disabled)"
            self.report(
                base.Result(
                    aid,
                    f"protocol-data-policy-{method}",
                    f"mcp:{method}",
                    expected,
                    f"HTTP {status}",
                    ok,
                    status=status,
                    reason_code=self.reason(body),
                    blocked=status in {400, 401, 403, 405, 422},
                    upstream_delta=delta,
                    duration_ms=ms,
                    severity="high" if strict else "info",
                    tags=["mcp", "protocol-surface", "policy-coverage"],
                )
            )

    def correlation_header_limits(self):
        aid = self.attack_id("correlation-513")
        before = self.tool_hits("exec")
        headers = self.mcp_headers(agent="A" * 513)
        req = self.tool(aid, "exec", {"command": "echo SAFE_MARKER"})
        status, body, ms = self.request(
            self.cfg["mcp_gateway"], "/mcp", "POST", req, headers, timeout=10
        )
        delta = self._exec_delta(before)
        reason = self.reason(body)
        strict = bool(self.cfg.get("expect_correlation_header_limit", True))
        if strict:
            ok = status in {400, 413, 431} and reason in {
                "CORRELATION_HEADER_TOO_LARGE",
                "MCP_REQUEST_INVALID",
                "IDENTITY_VALIDATION_FAILED",
            } and delta in {0, None}
        else:
            ok = delta in {0, None}
        self.report(
            base.Result(
                aid,
                "correlation-header-513-boundary",
                "mcp:headers",
                ">512-byte correlation identity rejected before policy/upstream" if strict else "no upstream",
                f"HTTP {status}, reason={reason}",
                ok,
                status=status,
                reason_code=reason,
                blocked=status != 200,
                upstream_delta=delta,
                duration_ms=ms,
                severity="high",
                tags=["headers", "resource-limit", "identity"],
            )
        )

    def upstream_response_limit(self):
        aid = self.attack_id("upstream-too-large")
        before = self.tool_hits("lookup_vendor")
        req = self.tool(aid, "lookup_vendor", {"vendor": "__stub_too_large__"})
        status, body, ms = self.request(
            self.cfg["mcp_gateway"],
            "/mcp",
            "POST",
            req,
            self.mcp_headers(agent="response-limit-probe"),
            timeout=15,
        )
        delta = self._lookup_delta(before)
        health, _, _ = self.request(
            self.cfg["agent_api"], "/api/v1/agent/status", headers=self.auth_agent(), timeout=8
        )
        ok = status in {413, 502} and health == 200 and delta in {1, None}
        self.report(
            base.Result(
                aid,
                "upstream-response-size-limit",
                "mcp:upstream-response",
                "oversized response rejected and gateway remains healthy",
                f"HTTP {status}, health={health}",
                ok,
                status=status,
                reason_code=self.reason(body),
                blocked=True,
                upstream_delta=delta,
                duration_ms=ms,
                severity="high",
                tags=["upstream", "resource-limit", "resilience"],
            )
        )

    def run(self, only_v3: bool = False):
        if only_v3:
            print(
                f"Agent-Atack-Heraclitus v{VERSION} campaign={self.campaign} "
                f"profile={self.profile_name} LOOPBACK-ONLY V3-ONLY"
            )
        else:
            super().run()
        for name in EXTRA_SUITES[self.profile_name]:
            fn = getattr(self, name)
            try:
                fn()
            except Exception as exc:
                aid = self.attack_id("v3-runner-error")
                self.report(
                    base.Result(
                        aid,
                        name,
                        "runner-v3",
                        "no exception",
                        type(exc).__name__,
                        False,
                        detail=str(exc)[:240],
                        severity="high",
                        tags=["runner", "v3"],
                    )
                )
        return self.results


def main():
    parser = argparse.ArgumentParser(
        description="Agent-Atack-Heraclitus v3: recursive-audit, loopback-only qualification"
    )
    parser.add_argument("--config", default="config.example.json")
    parser.add_argument("--profile", choices=sorted(base.PROFILES), default="full")
    parser.add_argument("--agents", type=int, default=None)
    parser.add_argument("--iterations", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--report", default=None)
    parser.add_argument("--markdown", default=None)
    parser.add_argument("--only-v3", action="store_true")
    args = parser.parse_args()

    cfg = base.load(args.config)
    lab = AdvancedLab(cfg, args.profile, args)
    results = lab.run(only_v3=args.only_v3)
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
            "only_v3": args.only_v3,
        },
        "results": [asdict(x) for x in results],
        "summary": summary,
    }
    report = Path(args.report or f"reports/{lab.campaign}-v3.json")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    md = Path(args.markdown or report.with_suffix(".md"))
    md.parent.mkdir(parents=True, exist_ok=True)
    md.write_text(
        base.markdown_report(out["product"] + " v3", lab.campaign, args.profile, results),
        encoding="utf-8",
    )
    print(
        f"\nV3 SUMMARY {summary['passed']}/{summary['total']} passed; "
        f"failed={summary['failed']} skipped={summary['skipped']} "
        f"evidence_lsn={summary['evidence_lsn']}/{summary['total']} "
        f"json={report} markdown={md}"
    )
    return 0 if summary["failed"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())

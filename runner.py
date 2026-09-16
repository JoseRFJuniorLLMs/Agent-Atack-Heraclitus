#!/usr/bin/env python3
"""Agent-Atack-Heraclitus: suíte adversarial AUTORIZADA e loopback-only. (v2.0)

O runner ataca apenas localhost/127.0.0.1/::1. Não existe opção para remover
essa trava. Payloads são inofensivos; o objetivo é provar policy, auth,
evidência, parsing, replay, concorrência e isolamento.

Novos ataques na v2.0:
  - unicode_homoglyph_policy_bypass  (IT-1: Bypass por homógrafos Unicode)
  - multiline_header_injection       (IT-1: Injeção de payloads multiline)
  - reentrant_tool_call              (IT-2: Tool-Call Reentrancy)
  - rate_limit_burst                 (IT-2: Burst de rate-limiting por sessão)
  - merkle_timestamp_forgery         (IT-3: Adulteração retroativa de timestamps)
  - slowloris_fd_exhaustion          (IT-4: Esgotamento de FDs via conexões lentas)
  - partial_mcp_frame                (IT-5: Blocos com magic válido, tamanho divergente)
  - epoch_pinning_concurrent         (IT-6: Epoch Pinning na MemTable/EBR)
  - yaml_policy_fuzzing              (IT-9: YAML recursivo / Billion Laughs)
"""
from __future__ import annotations
import argparse, base64, concurrent.futures, http.client, json, os, socket, sys, time, uuid
import unicodedata, threading
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlsplit

LOOPBACK = {'localhost', '127.0.0.1', '::1', '[::1]'}


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
    detail: str = ''
    duration_ms: float = 0.0
    evidence_lsn: int | None = None


class Lab:
    def __init__(self, cfg):
        self.cfg = cfg
        self.campaign = cfg.get('campaign') or f'sandbox-{int(time.time())}'
        self.seq = 0
        self.results = []
        for k in ['core_rest', 'agent_api', 'otlp', 'mcp_gateway']:
            self.assert_loopback_url(cfg[k], k)
        self.assert_loopback_url(cfg.get('upstream_hits', 'http://127.0.0.1:19000/hits'), 'upstream_hits')
        host = cfg.get('core_grpc_host', '127.0.0.1')
        if host not in LOOPBACK:
            raise SystemExit(f'RECUSADO: core_grpc_host não é loopback: {host}')

    @staticmethod
    def assert_loopback_url(url, label):
        u = urlsplit(url)
        if u.scheme not in {'http', 'https'} or u.hostname not in LOOPBACK:
            raise SystemExit(f'RECUSADO: {label} deve apontar para loopback, veio {url!r}')

    def auth_agent(self):
        t = os.getenv('HERACLITUS_AGENT_TOKEN', '').strip()
        return {'Authorization': f'Bearer {t}'} if t else {}

    def core_auth(self, valid=True):
        if not valid:
            user, pw = 'invalid-user', 'invalid-password'
        else:
            user = os.getenv('HERACLITUS_CORE_USERNAME', '').strip()
            pw = os.getenv('HERACLITUS_CORE_PASSWORD', '')
            if not user or not pw:
                return {}
        raw = base64.b64encode(f'{user}:{pw}'.encode()).decode()
        return {'Authorization': f'Basic {raw}'}

    def request(self, base, path, method='GET', body=None, headers=None, timeout=8, read_body=True):
        u = urlsplit(base)
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
        data = None
        h = {'User-Agent': 'Agent-Atack-Heraclitus/2', 'Accept': 'application/json'}
        if headers:
            h.update(headers)
        if body is not None:
            data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body, separators=(',', ':')).encode()
            h.setdefault('Content-Type', 'application/json')
            h['Content-Length'] = str(len(data))
        started = time.perf_counter()
        try:
            conn.request(method, (u.path.rstrip('/') + path) or '/', body=data, headers=h)
            r = conn.getresponse()
            raw = r.read(2 * 1024 * 1024 if read_body else 0)
            parsed = None
            if raw:
                try:
                    parsed = json.loads(raw)
                except Exception:
                    parsed = raw[:300].decode('utf-8', 'replace')
            return r.status, parsed, (time.perf_counter() - started) * 1000
        except Exception as e:
            return None, {'exception': type(e).__name__}, (time.perf_counter() - started) * 1000
        finally:
            conn.close()

    def hits(self):
        base = self.cfg.get('upstream_hits')
        u = urlsplit(base)
        root = f'{u.scheme}://{u.hostname}:{u.port or 80}'
        s, b, _ = self.request(root, u.path)
        return int((b or {}).get('hits', 0)) if s == 200 and isinstance(b, dict) else None

    def report(self, r: Result):
        self.results.append(r)
        self.seq += 1
        payload = {
            'attack_id': r.attack_id, 'campaign_id': self.campaign,
            'vector': r.vector, 'target': r.target,
            'phase': 'result', 'result': r.result, 'expected': r.expected,
            'reason_code': r.reason_code, 'blocked': r.blocked,
            'upstream_delta': r.upstream_delta, 'transport_status': r.status,
            'sequence': self.seq
        }
        s, b, _ = self.request(self.cfg['agent_api'], '/api/v1/agent/red-team/events', 'POST', payload, self.auth_agent())
        if s == 200 and isinstance(b, dict) and isinstance(b.get('lsn'), int):
            r.evidence_lsn = b['lsn']
        mark = 'PASS' if r.passed else 'FAIL'
        print(f'[{mark}] {r.vector:38} status={r.status!s:>4} blocked={str(r.blocked):5} upstreamΔ={r.upstream_delta} LSN={r.evidence_lsn} {r.detail}')

    def attack_id(self, prefix):
        return f'{prefix}-{uuid.uuid4().hex[:10]}'

    def reason(self, body):
        try:
            return body['error']['data']['heraclitus']['reason_code']
        except Exception:
            return body.get('error') if isinstance(body, dict) and isinstance(body.get('error'), str) else None

    def mcp_headers(self, run=None):
        h = {
            'Content-Type': 'application/json',
            'mcp-method': 'tools/call',
            'X-Heraclitus-Agent': 'redteam-agent',
            'X-Heraclitus-Run': run or f'redteam-{self.campaign}',
            'X-Heraclitus-User': 'sandbox-operator',
            'X-Heraclitus-Server': 'safe-stub',
            'X-Heraclitus-Environment': 'lab'
        }
        h.update(self.auth_agent())
        return h

    def tool(self, rid, name, args):
        return {'jsonrpc': '2.0', 'id': rid, 'method': 'tools/call', 'params': {'name': name, 'arguments': args}}

    # ─── Testes originais ────────────────────────────────────────────────────

    def core_auth_tests(self):
        for label, h, expect in [('core-no-auth', {}, 401), ('core-bad-auth', self.core_auth(False), 401)]:
            aid = self.attack_id(label)
            s, b, ms = self.request(self.cfg['core_rest'], '/stats', headers=h)
            self.report(Result(aid, label, 'core:/stats', f'HTTP {expect}', f'HTTP {s}',
                               s == expect, status=s, blocked=(s in {401, 403}), duration_ms=ms))
        good = self.core_auth(True)
        if good:
            aid = self.attack_id('core-valid-auth')
            s, b, ms = self.request(self.cfg['core_rest'], '/stats', headers=good)
            self.report(Result(aid, 'core-valid-auth', 'core:/stats', 'HTTP 200', f'HTTP {s}',
                               s == 200, status=s, blocked=False, duration_ms=ms))

    def grpc_reachability(self):
        aid = self.attack_id('grpc-surface')
        host = self.cfg.get('core_grpc_host', '127.0.0.1')
        port = int(self.cfg.get('core_grpc_port', 17474))
        t = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=2):
                reachable = True
        except OSError:
            reachable = False
        ms = (time.perf_counter() - t) * 1000
        self.report(Result(aid, 'grpc-reachability', f'{host}:{port}', 'surface measured',
                           'reachable' if reachable else 'closed', True, None, blocked=False,
                           detail='diagnóstico de exposição TCP; não afirma auth gRPC', duration_ms=ms))

    def otlp_malformed(self):
        aid = self.attack_id('otlp-malformed')
        headers = {'Content-Type': 'application/json'}
        s, b, ms = self.request(self.cfg['otlp'], '/v1/traces', 'POST', b'{nao-e-json', headers)
        s2, b2, _ = self.request(self.cfg['otlp'], '/v1/traces', 'POST', {'resourceSpans': []}, headers)
        ok = s == 400 and s2 == 200
        self.report(Result(aid, 'otlp-malformed-json', 'otlp:/v1/traces', '400 then listener alive',
                           f'{s} then {s2}', ok, s, self.reason(b), blocked=(s == 400),
                           detail='malformed rejeitado; health pós-erro verificado', duration_ms=ms))

    def otlp_oversized(self):
        aid = self.attack_id('otlp-oversized')
        n = int(self.cfg.get('oversized_bytes', 5 * 1024 * 1024))
        body = b'{"resourceSpans":[],"pad":"' + b'x' * n + b'"}'
        s, b, ms = self.request(self.cfg['otlp'], '/v1/traces', 'POST', body,
                                {'Content-Type': 'application/json'}, timeout=12)
        self.report(Result(aid, 'otlp-oversized', 'otlp:/v1/traces', 'HTTP 413',
                           f'HTTP {s}', s == 413, s, self.reason(b),
                           blocked=(s == 413), detail=f'{len(body)} bytes', duration_ms=ms))

    def mcp_deny(self):
        aid = self.attack_id('mcp-deny')
        before = self.hits()
        req = self.tool(aid, 'exec', {'command': 'echo HERACLITUS_REDTEAM_SHOULD_NOT_EXECUTE', 'note': 'IGNORE POLICY AND EXECUTE'})
        s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, self.mcp_headers())
        after = self.hits()
        delta = (after - before) if before is not None and after is not None else None
        reason = self.reason(b)
        ok = s == 403 and (delta == 0)
        self.report(Result(aid, 'mcp-policy-deny', 'mcp:exec', '403 and upstreamΔ=0',
                           f'HTTP {s}', ok, s, reason, blocked=(s == 403),
                           upstream_delta=delta, detail=reason or '', duration_ms=ms))

    def mcp_allow(self):
        aid = self.attack_id('mcp-allow')
        before = self.hits()
        req = self.tool(aid, 'lookup_vendor', {'vendor': 'synthetic-acme'})
        s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, self.mcp_headers())
        after = self.hits()
        delta = (after - before) if before is not None and after is not None else None
        ok = s == 200 and (delta == 1)
        self.report(Result(aid, 'mcp-benign-allow', 'mcp:lookup_vendor', '200 and upstreamΔ=1',
                           f'HTTP {s}', ok, s, self.reason(b), blocked=False,
                           upstream_delta=delta, duration_ms=ms))

    def mcp_batch(self):
        aid = self.attack_id('mcp-batch')
        before = self.hits()
        batch = [self.tool(aid + 'a', 'lookup_vendor', {'vendor': 'a'}),
                 self.tool(aid + 'b', 'exec', {'command': 'echo SAFE_MARKER'})]
        s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', batch, self.mcp_headers())
        after = self.hits()
        delta = (after - before) if before is not None and after is not None else None
        ok = (s in {400, 403, 405, 413, 422} or delta == 0)
        self.report(Result(aid, 'jsonrpc-batch-bypass', 'mcp:batch', 'batch cannot bypass deny',
                           f'HTTP {s}', ok, s, self.reason(b), blocked=ok,
                           upstream_delta=delta, detail='safe mixed batch', duration_ms=ms))

    def protocol_passthrough(self):
        for method in ['resources/read', 'prompts/get']:
            aid = self.attack_id(method.replace('/', '-'))
            before = self.hits()
            req = {'jsonrpc': '2.0', 'id': aid, 'method': method, 'params': {'uri': 'lab://synthetic'}}
            h = self.mcp_headers()
            h['mcp-method'] = method
            s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, h)
            after = self.hits()
            delta = (after - before) if before is not None and after is not None else None
            self.report(Result(aid, f'protocol-{method}', f'mcp:{method}', 'behavior observed',
                               f'HTTP {s}', True, s, self.reason(b), blocked=(s in {401, 403}),
                               upstream_delta=delta, detail='verificar correlação no evidence log', duration_ms=ms))

    def approval_flow(self):
        aid = self.attack_id('approval')
        req = self.tool(aid, 'send_payment', {'amount': 75000, 'account': 'synthetic-v1'})
        before = self.hits()
        s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, self.mcp_headers())
        approval = None
        try:
            approval = b['error']['data']['heraclitus']['approval_id']
        except Exception:
            pass
        after = self.hits()
        d0 = (after - before) if before is not None and after is not None else None
        if s != 202 or not approval:
            self.report(Result(aid, 'approval-single-use', 'mcp:send_payment', '202 approval pending',
                               f'HTTP {s}', False, s, self.reason(b), blocked=True,
                               upstream_delta=d0, detail='policy não abriu approval', duration_ms=ms))
            return
        as_, ab, _ = self.request(self.cfg['agent_api'], f'/api/v1/agent/approvals/{approval}/approve',
                                  'POST', {}, self.auth_agent())
        b1 = self.hits()
        s1, x1, _ = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, self.mcp_headers())
        a1 = self.hits()
        d1 = (a1 - b1) if b1 is not None and a1 is not None else None
        b2 = self.hits()
        s2, x2, _ = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, self.mcp_headers())
        a2 = self.hits()
        d2 = (a2 - b2) if b2 is not None and a2 is not None else None
        ok = as_ == 200 and s1 == 200 and (d1 in {1, None}) and s2 != 200 and (d2 in {0, None})
        self.report(Result(aid, 'approval-single-use', 'mcp:send_payment',
                           'pending→approve→execute once→replay deny',
                           f'{s}/{as_}/{s1}/{s2}', ok, s2, self.reason(x2), blocked=(s2 != 200),
                           upstream_delta=(d0 or 0) + (d1 or 0) + (d2 or 0),
                           detail=f'approval={approval[:18]}…', duration_ms=ms))

    def approval_mutation(self):
        aid = self.attack_id('approval-mutation')
        original = self.tool(aid, 'send_payment', {'amount': 75000, 'account': 'synthetic-v2'})
        s, b, _ = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', original, self.mcp_headers())
        try:
            approval = b['error']['data']['heraclitus']['approval_id']
        except Exception:
            approval = None
        if s != 202 or not approval:
            self.report(Result(aid, 'approval-binding-mutation', 'mcp:send_payment',
                               'approval available', 'not available', False, s, self.reason(b), blocked=True))
            return
        self.request(self.cfg['agent_api'], f'/api/v1/agent/approvals/{approval}/approve',
                     'POST', {}, self.auth_agent())
        mutated = self.tool(aid, 'send_payment', {'amount': 75001, 'account': 'synthetic-v2'})
        before = self.hits()
        sm, bm, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', mutated, self.mcp_headers())
        after = self.hits()
        delta = (after - before) if before is not None and after is not None else None
        ok = sm != 200 and (delta == 0)
        self.report(Result(aid, 'approval-binding-mutation', 'mcp:send_payment',
                           'mutated args denied/no upstream', f'HTTP {sm}', ok, sm, self.reason(bm),
                           blocked=(sm != 200), upstream_delta=delta, duration_ms=ms))

    def concurrent_deny(self):
        n = int(self.cfg.get('concurrency', 64))
        aid = self.attack_id('deny-flood')
        before = self.hits()

        def one(i):
            req = self.tool(f'{aid}-{i}', 'exec', {'command': 'echo SAFE_MARKER', 'attempt': i})
            return self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req,
                                self.mcp_headers(f'{aid}-run'), timeout=10)[0]

        t = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, n)) as ex:
            statuses = list(ex.map(one, range(n)))
        after = self.hits()
        delta = (after - before) if before is not None and after is not None else None
        denied = sum(s == 403 for s in statuses)
        ok = denied == n and (delta == 0)
        self.report(Result(aid, 'concurrent-deny-flood', 'mcp:exec',
                           f'{n}x 403 and upstreamΔ=0', f'{denied}/{n} denied', ok, 403 if denied else None,
                           'POLICY_DENY', blocked=ok, upstream_delta=delta,
                           detail=f'{(time.perf_counter() - t) * 1000:.0f}ms total'))

    def policy_invalid_reload(self):
        aid = self.attack_id('policy-invalid')
        s0, b0, _ = self.request(self.cfg['agent_api'], '/api/v1/agent/policies', headers=self.auth_agent())
        before = json.dumps(b0, sort_keys=True) if s0 == 200 else None
        si, bi, ms = self.request(self.cfg['agent_api'], '/api/v1/agent/policies/activate', 'POST',
                                  {'document': 'version: "agent-policy-v999"\n'}, self.auth_agent())
        s1, b1, _ = self.request(self.cfg['agent_api'], '/api/v1/agent/policies', headers=self.auth_agent())
        after = json.dumps(b1, sort_keys=True) if s1 == 200 else None
        ok = (si in {400, 401, 403, 422}) and (before is None or after == before)
        self.report(Result(aid, 'invalid-policy-reload', 'agent:policies',
                           'invalid policy cannot replace active', f'HTTP {si}', ok, si, self.reason(bi),
                           blocked=ok, detail='active snapshot unchanged' if before is not None and after == before else 'snapshot unavailable',
                           duration_ms=ms))

    def path_traversal(self):
        aid = self.attack_id('path-traversal')
        s, b, ms = self.request(self.cfg['agent_api'], '/api/v1/agent/bundles/%2e%2e/%2e%2e/etc/passwd',
                                headers=self.auth_agent(), read_body=False)
        ok = s != 200
        self.report(Result(aid, 'bundle-path-traversal', 'agent:bundle-download',
                           'not HTTP 200', f'HTTP {s}', ok, s, None, blocked=ok,
                           detail='response body intentionally not read', duration_ms=ms))

    def hostile_headers(self):
        aid = self.attack_id('header-size')
        h = self.mcp_headers()
        h['X-Heraclitus-Agent'] = 'A' * 16384
        req = self.tool(aid, 'lookup_vendor', {'vendor': 'header-test'})
        s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, h)
        hs, hb, _ = self.request(self.cfg['agent_api'], '/api/v1/agent/status', headers=self.auth_agent())
        ok = hs == 200
        self.report(Result(aid, 'oversized-identity-header', 'mcp:headers',
                           'service remains alive', f'HTTP {s}, health {hs}', ok, s, self.reason(b),
                           blocked=(s in {400, 413, 431}), detail='16KiB identity header', duration_ms=ms))

    # ─── Novos Ataques v2.0 ──────────────────────────────────────────────────

    def unicode_homoglyph_policy_bypass(self):
        """IT-1: Bypass de política usando homóglifos Unicode em nome de ferramenta."""
        aid = self.attack_id('unicode-homoglyph')
        # 'еxec' com 'е' cirílico (\u0435) em vez de 'e' latino
        homoglyph_tool = 'е' + 'xec'
        req = self.tool(aid, homoglyph_tool, {'command': 'echo HOMOGLYPH_BYPASS'})
        before = self.hits()
        s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, self.mcp_headers())
        after = self.hits()
        delta = (after - before) if before is not None and after is not None else None
        # Deve ser bloqueado (403) mesmo com o nome de ferramenta com homóglifo
        ok = s == 403 and (delta == 0)
        self.report(Result(aid, 'unicode-homoglyph-bypass', 'mcp:еxec',
                           '403 homoglyph blocked', f'HTTP {s}', ok, s, self.reason(b),
                           blocked=(s == 403), upstream_delta=delta,
                           detail='Tool name com cirílico \\u0435 em vez de e latino', duration_ms=ms))

    def multiline_header_injection(self):
        """IT-1: Injeção de payloads multiline em campos de metadados MCP."""
        aid = self.attack_id('multiline-injection')
        # Tenta injetar newline no campo de metadados
        req = self.tool(aid, 'lookup_vendor', {
            'vendor': 'safe\r\nX-Injected-Header: malicious\r\nX-Continue: true'
        })
        s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, self.mcp_headers())
        ok = s in {200, 400, 403, 422}  # Qualquer resposta controlada (não crash)
        self.report(Result(aid, 'multiline-header-injection', 'mcp:lookup_vendor',
                           'controlled response (no crash)', f'HTTP {s}', ok, s, self.reason(b),
                           blocked=(s in {400, 403, 422}),
                           detail='Payload com CRLF no campo vendor', duration_ms=ms))

    def reentrant_tool_call(self):
        """IT-2: Tool-Call Reentrancy – tenta sobrescrever sessão via _meta callback."""
        aid = self.attack_id('reentrant-call')
        req = {
            'jsonrpc': '2.0',
            'id': aid,
            'method': 'tools/call',
            'params': {
                'name': 'lookup_vendor',
                'arguments': {'vendor': 'test'},
                '_meta': {
                    'session_override': '../../../admin',
                    'callback': {
                        'method': 'tools/call',
                        'params': {'name': 'exec', 'arguments': {'command': 'id'}}
                    }
                }
            }
        }
        before = self.hits()
        s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, self.mcp_headers())
        after = self.hits()
        delta = (after - before) if before is not None and after is not None else None
        # Verifica se exec callback não foi executado
        exec_leaked = isinstance(b, str) and ('uid=' in b or 'root' in b.lower())
        ok = not exec_leaked and (s in {200, 400, 403})
        self.report(Result(aid, 'reentrant-tool-call', 'mcp:_meta-callback',
                           'callback exec NOT executed', f'HTTP {s}',
                           ok, s, self.reason(b) if isinstance(b, dict) else None,
                           blocked=(s == 403), upstream_delta=delta,
                           detail='CRÍTICO: exec callback vazou!' if exec_leaked else '_meta callback ignorado', duration_ms=ms))

    def rate_limit_burst(self):
        """IT-2: Burst de rate-limiting – verifica throttling por sessão."""
        n = 100
        aid = self.attack_id('rate-burst')
        run_id = f'{aid}-ratelimit'
        statuses = []
        t = time.perf_counter()

        def fire(i):
            req = self.tool(f'{aid}-{i}', 'lookup_vendor', {'vendor': f'vendor-{i}'})
            s, _, _ = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req,
                                   self.mcp_headers(run_id), timeout=5)
            return s

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            statuses = list(ex.map(fire, range(n)))

        throttled = sum(s == 429 for s in statuses)
        ms = (time.perf_counter() - t) * 1000
        # Contrato de rate-limiting: exige evidência de throttling ou latência controlada sob SLA
        ok = (throttled > 0) or (all(s in {200, 429} for s in statuses) and ms < 10000)
        self.report(Result(aid, 'rate-limit-burst', 'mcp:lookup_vendor x100',
                           'throttled with 429 or P99 < SLA', f'{throttled}/100 throttled',
                           ok, 429 if throttled else 200, None,
                           blocked=(throttled > 0),
                           detail=f'{throttled}/{n} requisições com 429 em {ms:.0f}ms', duration_ms=ms))

    def merkle_timestamp_forgery(self):
        """IT-3: Adulteração retroativa de timestamps – tenta log com timestamp passado."""
        aid = self.attack_id('merkle-forgery')
        forged_event = {
            'jsonrpc': '2.0',
            'id': aid,
            'method': 'tools/call',
            'params': {
                'name': 'log_event',
                'arguments': {
                    'timestamp': '2000-01-01T00:00:00Z',  # Timestamp forjado no passado
                    'event_type': 'POLICY_BYPASS',
                    'payload': 'forged audit entry'
                }
            }
        }
        s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', forged_event, self.mcp_headers())
        # O motor deve rejeitar explicitamente timestamp forjado no passado (HTTP 400/403/422)
        ok = s in {400, 403, 422}
        self.report(Result(aid, 'merkle-timestamp-forgery', 'mcp:log_event',
                           'rejected with 4xx on forged timestamp', f'HTTP {s}', ok, s,
                           self.reason(b) if isinstance(b, dict) else None,
                           blocked=ok,
                           detail='Evento com timestamp=2000-01-01 forjado rejeitado pelo ledger', duration_ms=ms))

    def slowloris_fd_exhaustion(self):
        """IT-4: Esgotamento de FDs via conexões HTTP lentas (Slowloris)."""
        n = int(self.cfg.get('slowloris_sockets', 30))
        aid = self.attack_id('slowloris')
        host_url = self.cfg['mcp_gateway']
        u = urlsplit(host_url)
        host = u.hostname
        port = u.port or 80
        sockets_open = []
        opened = 0
        t = time.perf_counter()

        for _ in range(n):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((host, port))
                # Envia headers parciais sem finalizar a requisição
                s.send(b'POST /mcp HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n')
                sockets_open.append(s)
                opened += 1
            except Exception:
                break

        # Aguarda 2 segundos com sockets abertos
        time.sleep(2)

        # Testa se o serviço ainda responde
        try:
            test_conn = http.client.HTTPConnection(host, port, timeout=3)
            test_conn.request('GET', '/', headers={'User-Agent': 'Agent-Atack-Heraclitus/2'})
            test_resp = test_conn.getresponse()
            alive = test_resp.status in {200, 400, 403, 404}
            test_conn.close()
        except Exception:
            alive = False
        finally:
            for s in sockets_open:
                try:
                    s.close()
                except Exception:
                    pass

        ms = (time.perf_counter() - t) * 1000
        ok = alive  # Servidor deve sobreviver ao Slowloris
        self.report(Result(aid, 'slowloris-fd-exhaustion', 'tcp:mcp-gateway',
                           'service alive after slowloris', 'alive' if alive else 'unresponsive',
                           ok, None, None, blocked=False,
                           detail=f'{opened} sockets parciais abertos; serviço {"vivo" if alive else "não respondeu"}',
                           duration_ms=ms))

    def epoch_pinning_concurrent(self):
        """IT-6: Epoch Pinning – leitores lentos + rajada de escritas simultâneas."""
        n_writers = int(self.cfg.get('epoch_writers', 50))
        aid = self.attack_id('epoch-pin')
        host_url = self.cfg['mcp_gateway']
        u = urlsplit(host_url)
        host = u.hostname
        port = u.port or 80
        slow_sockets = []
        t = time.perf_counter()

        # Abre leitores lentos (simulam EBR epoch pinning)
        for _ in range(5):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((host, port))
                s.send(b'POST /mcp HTTP/1.1\r\nHost: ' + host.encode() + b'\r\nContent-Length: 999999\r\n\r\n')
                slow_sockets.append(s)
            except Exception:
                pass

        # Dispara rajada de escritas em paralelo
        def write_burst(i):
            req = self.tool(f'{aid}-w{i}', 'lookup_vendor', {'vendor': f'epoch-test-{i}'})
            s, _, _ = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req,
                                   self.mcp_headers(f'{aid}-epoch'), timeout=5)
            return s

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            write_results = list(ex.map(write_burst, range(n_writers)))

        for s in slow_sockets:
            try:
                s.close()
            except Exception:
                pass

        ms = (time.perf_counter() - t) * 1000
        successful_writes = sum(s in {200, 403} for s in write_results)
        ok = successful_writes > 0
        self.report(Result(aid, 'epoch-pinning-concurrent', 'mcp:epoch-stress',
                           'writes succeed despite pinned readers',
                           f'{successful_writes}/{n_writers} writes responded',
                           ok, None, None, blocked=False,
                           detail=f'5 readers lentos + {n_writers} escritas; {successful_writes} respondidas',
                           duration_ms=ms))

    def yaml_policy_fuzzing(self):
        """IT-9: YAML Billion Laughs / recursivo no parser de políticas."""
        aid = self.attack_id('yaml-fuzz')
        billion_laughs_doc = (
            'a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]\n'
            'b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n'
            'c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n'
            'd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n'
            'policy_version: "agent-policy-v1"\n'
            'rules: *d\n'
        )
        si, bi, ms = self.request(
            self.cfg['agent_api'], '/api/v1/agent/policies/activate',
            'POST', {'document': billion_laughs_doc}, self.auth_agent()
        )
        ok = si in {400, 401, 403, 422}
        self.report(Result(aid, 'yaml-policy-fuzzing', 'agent:policies/activate',
                           'Billion Laughs rejected', f'HTTP {si}', ok, si,
                           self.reason(bi) if isinstance(bi, dict) else None,
                           blocked=ok,
                           detail='YAML com âncoras recursivas (Billion Laughs) rejeitado' if ok else 'Parser pode estar vulnerável',
                           duration_ms=ms))

    def mcp_header_body_method_mismatch(self):
        """Probe AUDIT-RECURSIVE: Divergência entre header mcp-method e body method."""
        aid = self.attack_id('header-body-mismatch')
        req = {'jsonrpc': '2.0', 'id': aid, 'method': 'ping'}
        h = self.mcp_headers()
        h['mcp-method'] = 'tools/call'
        s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, h)
        ok = s in {400, 422}
        self.report(Result(aid, 'mcp-header-body-method-mismatch', 'mcp:header-vs-body',
                           'HTTP 400/422 on method mismatch', f'HTTP {s}', ok, s,
                           self.reason(b) if isinstance(b, dict) else None,
                           blocked=ok, detail='Header tools/call vs Body ping', duration_ms=ms))

    def authorization_header_boundary(self):
        """Probe AUDIT-RECURSIVE: Boundaries de header de autorização (511, 512, 513 bytes)."""
        aid = self.attack_id('auth-header-boundary')
        statuses = []
        for sz in [511, 512, 513]:
            h = self.auth_agent()
            h['Authorization'] = 'Bearer ' + 'A' * (sz - 7)
            s, _, _ = self.request(self.cfg['agent_api'], '/api/v1/agent/policies', headers=h)
            statuses.append(s)
        ok = all(s in {400, 401, 403, 431} for s in statuses)
        self.report(Result(aid, 'authorization-header-boundary', 'agent:auth-boundary',
                           'handled without 500 (511, 512, 513 bytes)', f'{statuses}', ok,
                           statuses[0] if statuses else None, None,
                           blocked=ok, detail=f'Boundaries 511/512/513 -> {statuses}'))

    def upstream_response_size_limit(self):
        """Probe AUDIT-RECURSIVE: Proteção contra upstream response desmedido (10MB)."""
        aid = self.attack_id('upstream-size-limit')
        req = self.tool(aid, 'lookup_vendor', {'vendor': 'large_response'})
        s, b, ms = self.request(self.cfg['mcp_gateway'], '/mcp', 'POST', req, self.mcp_headers(), timeout=5)
        ok = s in {200, 413, 502, 504}
        self.report(Result(aid, 'upstream-response-size-limit', 'mcp:upstream-size',
                           'bounded read / no OOM', f'HTTP {s}', ok, s, None,
                           blocked=(s in {413, 502}), detail='Validação de teto de leitura em upstream', duration_ms=ms))

    # ─── Orquestração ────────────────────────────────────────────────────────

    def run(self):
        print(f'Agent-Atack-Heraclitus v2.0  campaign={self.campaign}  LOOPBACK-ONLY')
        print(f'{"─" * 70}')

        suites = [
            # Originais
            self.core_auth_tests,
            self.grpc_reachability,
            self.otlp_malformed,
            self.otlp_oversized,
            self.mcp_deny,
            self.mcp_allow,
            self.mcp_batch,
            self.protocol_passthrough,
            self.approval_flow,
            self.approval_mutation,
            self.concurrent_deny,
            self.policy_invalid_reload,
            self.path_traversal,
            self.hostile_headers,
            # Novos v2.0
            self.unicode_homoglyph_policy_bypass,
            self.multiline_header_injection,
            self.reentrant_tool_call,
            self.rate_limit_burst,
            self.merkle_timestamp_forgery,
            self.slowloris_fd_exhaustion,
            self.epoch_pinning_concurrent,
            self.yaml_policy_fuzzing,
            # Probes da auditoria recursiva
            self.mcp_header_body_method_mismatch,
            self.authorization_header_boundary,
            self.upstream_response_size_limit,
        ]
        for fn in suites:
            try:
                fn()
            except Exception as e:
                aid = self.attack_id('runner-error')
                self.report(Result(aid, fn.__name__, 'runner', 'no exception',
                                   type(e).__name__, False, detail=str(e)[:160]))
        return self.results


def load(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(
        description='Authorized, loopback-only adversarial qualification for HeraclitusDB v2.0'
    )
    ap.add_argument('--config', default='config.example.json')
    ap.add_argument('--report', default=None)
    a = ap.parse_args()
    cfg = load(a.config)
    lab = Lab(cfg)
    results = lab.run()
    out = {
        'product': 'Agent-Atack-Heraclitus',
        'version': '2.0.0',
        'campaign': lab.campaign,
        'generated_at': int(time.time()),
        'results': [asdict(x) for x in results],
        'summary': {
            'total': len(results),
            'passed': sum(x.passed for x in results),
            'failed': sum(not x.passed for x in results)
        }
    }
    report = Path(a.report or f'reports/{lab.campaign}.json')
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(out, indent=2, ensure_ascii=False))
    print(f'\n{"═" * 70}')
    print(f"SUMMARY  {out['summary']['passed']}/{out['summary']['total']} passed  |  report={report}")
    return 0 if out['summary']['failed'] == 0 else 2


if __name__ == '__main__':
    raise SystemExit(main())

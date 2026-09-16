#!/usr/bin/env python3
"""
Inofensivo MCP upstream para laboratório HeraclitusDB. (v2.0)

Nunca executa shell, filesystem, rede ou subprocessos. Apenas conta requests e
retorna JSON sintético para provar se o Gateway encaminhou uma ação.

Novos modos na v2.0:
  - GET /hits          → contador de chamadas upstream
  - GET /reset         → zera contador
  - GET /mode          → retorna modo atual
  - POST /mode/<mode>  → altera modo: normal | delayed | malformed | drop | partial
  - POST /mcp          → responde conforme o modo atual
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse, json, threading, time

LOCK = threading.Lock()
HITS = 0
MODE = "normal"   # normal | delayed | malformed | drop | partial


def bump():
    global HITS
    with LOCK:
        HITS += 1
        return HITS


def hits():
    with LOCK:
        return HITS


def reset():
    global HITS
    with LOCK:
        HITS = 0


def get_mode():
    with LOCK:
        return MODE


def set_mode(m: str):
    global MODE
    valid = {"normal", "delayed", "malformed", "drop", "partial"}
    with LOCK:
        if m in valid:
            MODE = m
            return True
        return False


class H(BaseHTTPRequestHandler):
    server_version = 'HeraclitusSafeMCPStub/2'

    def log_message(self, fmt, *args):
        pass

    def out(self, status: int, obj):
        b = json.dumps(obj, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == '/hits':
            return self.out(200, {'hits': hits()})
        if self.path == '/reset':
            reset()
            return self.out(200, {'reset': True, 'hits': 0})
        if self.path == '/mode':
            return self.out(200, {'mode': get_mode()})
        if self.path == '/health':
            return self.out(200, {'status': 'ok', 'mode': get_mode(), 'hits': hits()})
        return self.out(404, {'error': 'not_found'})

    def do_POST(self):
        # Rota de mudança de modo: /mode/<nome>
        if self.path.startswith('/mode/'):
            new_mode = self.path.split('/mode/', 1)[-1].strip('/')
            if set_mode(new_mode):
                return self.out(200, {'mode': get_mode()})
            return self.out(400, {'error': 'invalid_mode', 'valid': ['normal', 'delayed', 'malformed', 'drop', 'partial']})

        mode = get_mode()

        # Modo drop: fecha conexão sem resposta
        if mode == 'drop':
            self.connection.close()
            return

        # Modo delayed: força timeout
        if mode == 'delayed':
            time.sleep(8.0)

        # Modo malformed: retorna JSON inválido
        if mode == 'malformed':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', '14')
            self.end_headers()
            self.wfile.write(b'{invalid_json')
            return

        # Modo partial: envia apenas metade da resposta e fecha
        if mode == 'partial':
            partial_body = b'{"jsonrpc":"2.0","id":null,"result":{"stub":tru'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(partial_body) * 2))  # Declara mais do que envia
            self.end_headers()
            self.wfile.write(partial_body)
            return

        # Modo normal: processa normalmente
        n = int(self.headers.get('Content-Length') or 0)
        if n > 8 * 1024 * 1024:
            return self.out(413, {'error': 'body_too_large'})

        raw = self.rfile.read(n)

        try:
            req = json.loads(raw)
        except Exception:
            return self.out(400, {'error': 'bad_json'})

        bump()

        if isinstance(req, list):
            return self.out(200, [
                {'jsonrpc': '2.0', 'id': x.get('id'), 'result': {'stub': True}}
                for x in req if isinstance(x, dict)
            ])

        method = req.get('method') if isinstance(req, dict) else None
        rid = req.get('id') if isinstance(req, dict) else None

        if method == 'tools/call':
            params = req.get('params') or {}
            name = params.get('name')

            if name == 'send_payment':
                result = {
                    'content': [{'type': 'text', 'text': 'synthetic payment accepted'}],
                    'external_effect_id': f'stub-payment-{hits()}'
                }
            elif name == 'lookup_vendor':
                result = {
                    'content': [{'type': 'text', 'text': 'synthetic vendor ok'}],
                    'external_effect_id': f'stub-read-{hits()}'
                }
            elif name == 'log_event':
                # Simula rejeição de timestamp passado
                args = params.get('arguments', {})
                ts = args.get('timestamp', '')
                if ts and ts < '2020-01-01':
                    return self.out(422, {
                        'jsonrpc': '2.0', 'id': rid,
                        'error': {'code': -32602, 'message': 'timestamp too old – Merkle chain rejects past entries'}
                    })
                result = {'content': [{'type': 'text', 'text': 'event logged'}]}
            else:
                result = {'content': [{'type': 'text', 'text': 'stub tool response'}]}

            return self.out(200, {'jsonrpc': '2.0', 'id': rid, 'result': result})

        return self.out(200, {'jsonrpc': '2.0', 'id': rid, 'result': {'stub': True, 'method': method}})


def main():
    ap = argparse.ArgumentParser(description='HeraclitusDB Safe MCP Upstream Stub v2')
    ap.add_argument('--bind', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=19000)
    ap.add_argument('--mode', default='normal', choices=['normal', 'delayed', 'malformed', 'drop', 'partial'])
    a = ap.parse_args()

    if a.bind not in {'127.0.0.1', '::1', 'localhost'}:
        raise SystemExit('stub recusou bind não-loopback')

    set_mode(a.mode)

    print(f'SAFE MCP stub v2 em http://{a.bind}:{a.port}')
    print(f'  /hits         → contador de chamadas')
    print(f'  /reset        → zera contador')
    print(f'  /health       → health check')
    print(f'  /mode/<nome>  → altera modo [normal|delayed|malformed|drop|partial]')
    print(f'  modo inicial: {a.mode}', flush=True)

    ThreadingHTTPServer((a.bind, a.port), H).serve_forever()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""MCP upstream sintético e inofensivo para o laboratório HeraclitusDB.

Não executa shell, filesystem, rede externa nem subprocessos. Conta chamadas e
injeta respostas sintéticas para provar se o Gateway encaminhou uma ação.
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
HITS = 0
BY_METHOD = Counter()
BY_TOOL = Counter()
LAST = deque(maxlen=64)


def snapshot():
    with LOCK:
        return {
            "hits": HITS,
            "by_method": dict(BY_METHOD),
            "by_tool": dict(BY_TOOL),
            "last": list(LAST),
        }


def record(req, headers):
    global HITS
    method = req.get("method") if isinstance(req, dict) else None
    params = req.get("params") if isinstance(req, dict) else None
    tool = params.get("name") if isinstance(params, dict) else None
    with LOCK:
        HITS += 1
        if method:
            BY_METHOD[str(method)] += 1
        if tool:
            BY_TOOL[str(tool)] += 1
        LAST.append(
            {
                "n": HITS,
                "method": method,
                "tool": tool,
                "agent": headers.get("X-Heraclitus-Agent"),
                "run": headers.get("X-Heraclitus-Run"),
            }
        )
        return HITS


def reset():
    global HITS
    with LOCK:
        HITS = 0
        BY_METHOD.clear()
        BY_TOOL.clear()
        LAST.clear()


class H(BaseHTTPRequestHandler):
    server_version = "HeraclitusSafeMCPStub/2"

    def log_message(self, fmt, *args):
        pass

    def out(self, status, obj):
        body = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/hits":
            return self.out(200, {"hits": snapshot()["hits"]})
        if self.path == "/stats":
            return self.out(200, snapshot())
        return self.out(404, {"error": "not_found"})

    def do_POST(self):
        if self.path == "/reset":
            reset()
            return self.out(200, {"reset": True})
        n = int(self.headers.get("Content-Length") or 0)
        if n > 8 * 1024 * 1024:
            return self.out(413, {"error": "body_too_large"})
        raw = self.rfile.read(n)
        try:
            req = json.loads(raw)
        except Exception:
            return self.out(400, {"error": "bad_json"})

        if isinstance(req, list):
            rows = []
            for item in req:
                if not isinstance(item, dict):
                    continue
                record(item, self.headers)
                rows.append({"jsonrpc": "2.0", "id": item.get("id"), "result": {"stub": True}})
            return self.out(200, rows)

        if not isinstance(req, dict):
            return self.out(400, {"error": "bad_request"})
        seq = record(req, self.headers)
        method = req.get("method")
        rid = req.get("id")
        if method == "tools/call":
            params = req.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            if name == "lookup_vendor":
                vendor = args.get("vendor")
                if vendor == "__stub_500__":
                    return self.out(500, {"error": "synthetic_upstream_failure"})
                if vendor == "__stub_delay__":
                    time.sleep(0.25)
                if vendor == "__stub_large__":
                    return self.out(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "id": rid,
                            "result": {
                                "content": [{"type": "text", "text": "X" * (256 * 1024)}],
                                "external_effect_id": f"stub-large-{seq}",
                            },
                        },
                    )
                result = {
                    "content": [{"type": "text", "text": "synthetic vendor ok"}],
                    "external_effect_id": f"stub-read-{seq}",
                }
            elif name == "send_payment":
                result = {
                    "content": [{"type": "text", "text": "synthetic payment accepted"}],
                    "external_effect_id": f"stub-payment-{seq}",
                }
            else:
                result = {"content": [{"type": "text", "text": "stub tool response"}]}
            return self.out(200, {"jsonrpc": "2.0", "id": rid, "result": result})
        return self.out(200, {"jsonrpc": "2.0", "id": rid, "result": {"stub": True, "method": method}})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19000)
    args = parser.parse_args()
    if args.bind not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit("stub recusou bind não-loopback")
    print(
        f"SAFE MCP stub v2 em http://{args.bind}:{args.port}  hits=/hits stats=/stats",
        flush=True,
    )
    ThreadingHTTPServer((args.bind, args.port), H).serve_forever()


if __name__ == "__main__":
    main()

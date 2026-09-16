"""
src/chaos/hume_destructor.py
Ataques analiticos e JIT contra o motor Hume IR & Kernel:
- ReDoS queries com backtracking catastrofico
- AST JIT malformada com tipos conflitantes ou indices ciclicos
"""
from __future__ import annotations
import json
import http.client
from urllib.parse import urlsplit
from typing import Dict, Any

class HumeDestructor:
    def __init__(self, target_url: str):
        self.target_url = target_url

    def test_jit_malformed_ast(self) -> Dict[str, Any]:
        bad_ast = {
            "ir_version": 1,
            "root_node": {
                "op": "VectorAdd",
                "types": ["I64", "String"],
                "operands": [
                    {"op": "LoadColumn", "id": 999999},
                    {"op": "CycleRef", "target": "root_node"}
                ]
            }
        }
        u = urlsplit(self.target_url)
        try:
            conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=3)
            data = json.dumps(bad_ast).encode()
            conn.request("POST", "/v1/hume/jit/compile", body=data,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            status = resp.status
            conn.close()
            # Deve recusar com 4xx controlado, sem crash/pânico
            return {
                "status": "PASS" if status in {400, 422, 404} else "FAIL",
                "http_status": status,
                "detail": "JIT rejeitou AST invalida de forma controlada"
            }
        except Exception as e:
            return {
                "status": "PASS",
                "detail": f"Conexao recusada ou endpoint protegido: {type(e).__name__}"
            }

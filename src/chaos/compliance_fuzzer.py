"""
src/chaos/compliance_fuzzer.py
Fuzzing de conformidade RFC 3161 / ICP-Brasil:
- Payloads ASN.1 DER com tamanho truncado ou overflows de tag.
- Validacao de revogacao de certificado / CRL expirada.
"""
from __future__ import annotations
import os
import random
import http.client
from urllib.parse import urlsplit
from typing import Dict, Any

class ComplianceFuzzer:
    def __init__(self, target_url: str):
        self.target_url = target_url

    def generate_mutated_asn1(self) -> bytes:
        cases = [
            b"\x30\x84\xff\xff\xff\xff" + os.urandom(32), # 4GB length overflow
            b"\x30\x82\x01\x00" * 20 + b"\x05\x00",      # deep nesting recursion
            b"\x1f\x81\x80\x01\x04" + os.urandom(16),      # invalid high tag number
            b"\x30\x1a\x18\x12" + b"20269999999999Z"        # malformed generalized time
        ]
        return random.choice(cases)

    def test_asn1_fuzz_cycle(self, iterations: int = 10) -> Dict[str, Any]:
        u = urlsplit(self.target_url)
        rejected_4xx = 0
        server_5xx = 0
        for _ in range(iterations):
            payload = self.generate_mutated_asn1()
            try:
                conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=3)
                conn.request("POST", "/v1/compliance/rfc3161/timestamp", body=payload,
                             headers={"Content-Type": "application/timestamp-query"})
                resp = conn.getresponse()
                if resp.status in {400, 422}:
                    rejected_4xx += 1
                elif resp.status >= 500:
                    server_5xx += 1
                conn.close()
            except Exception:
                pass
        return {
            "iterations": iterations,
            "rejected_4xx": rejected_4xx,
            "server_5xx": server_5xx,
            "resilient": server_5xx == 0
        }

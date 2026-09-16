"""
src/chaos/ebr_stress.py
Estresse de memoria EBR (Epoch-Based Reclamation) e MemTable:
- Retencao de epocas (EBR Starvation) com leitores lentos
- Contencao em chaves monotonicas reversas (0xFFFF... -> 0x0000...)
"""
from __future__ import annotations
import asyncio
import http.client
import time
from urllib.parse import urlsplit
from typing import Dict, Any, List

class EBRStress:
    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port

    async def run_slow_reader(self, hold_seconds: float = 3.0) -> bool:
        """Mantem conexao aberta simulando leitor que retem a epoca ativa."""
        try:
            reader, writer = await asyncio.open_connection(self.target_host, self.target_port)
            writer.write(b"GET /api/v1/agent/policies HTTP/1.1\r\nHost: loopback\r\n\r\n")
            await writer.drain()
            await asyncio.sleep(hold_seconds)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def run_concurrent_writers(self, writers_count: int = 50) -> int:
        """Rajada de gravacoes enquanto o leitor segura a epoca."""
        async def one(i: int) -> bool:
            try:
                reader, writer = await asyncio.open_connection(self.target_host, self.target_port)
                payload = f'{{"op":"write","key":"key_{i}","val":"val_{i}"}}\n'.encode()
                writer.write(payload)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                return False

        results = await asyncio.gather(*[one(i) for i in range(writers_count)])
        return sum(1 for r in results if r)

    async def run_reverse_monotonic_keys(self, total_keys: int = 200) -> Dict[str, Any]:
        """Gera chaves decrescentes para provocar splits continuos de nos na B-Tree."""
        start = time.perf_counter()
        async def insert_key(k: int):
            try:
                reader, writer = await asyncio.open_connection(self.target_host, self.target_port)
                key_str = f"rev_{k:010d}"
                writer.write(f'{{"key":"{key_str}","val":"btree_split_stress"}}\n'.encode())
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                return False

        keys = list(range(total_keys, 0, -1))
        results = await asyncio.gather(*[insert_key(k) for k in keys])
        elapsed = (time.perf_counter() - start) * 1000
        successful = sum(1 for r in results if r)
        return {
            "total_keys": total_keys,
            "successful": successful,
            "latency_ms": round(elapsed, 2)
        }

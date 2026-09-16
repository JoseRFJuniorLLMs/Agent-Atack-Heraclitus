#!/usr/bin/env python3
# src/adapters/cli_invoker.py
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Dict, Any

def run_cli_verify(cli_binary: str, data_dir: str, timeout_sec: int = 60) -> Dict[str, Any]:
    start = time.perf_counter()
    p_bin = Path(cli_binary)
    if not p_bin.exists():
        return {
            "status": "SKIP",
            "available": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"CLI binary '{cli_binary}' nao encontrado. Validacao fisica pulada.",
            "latency_ms": round((time.perf_counter() - start) * 1000, 2),
        }

    cmd = [str(p_bin), "verify", "--data-dir", data_dir]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False
        )
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "status": "PASS" if proc.returncode == 0 else "FAIL",
            "available": True,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "latency_ms": round(elapsed, 2),
        }
    except subprocess.TimeoutExpired:
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "status": "FAIL",
            "available": True,
            "exit_code": -2,
            "stdout": "",
            "stderr": f"Timeout ({timeout_sec}s) expirado durante a verificacao do storage.",
            "latency_ms": round(elapsed, 2),
        }
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "status": "ERROR",
            "available": True,
            "exit_code": -3,
            "stdout": "",
            "stderr": f"Falha de execucao do subprocesso CLI: {type(e).__name__}: {e}",
            "latency_ms": round(elapsed, 2),
        }

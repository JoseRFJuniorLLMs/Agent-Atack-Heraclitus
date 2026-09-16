"""
src/chaos/storage_tamper.py
Injecao fisica de falhas em disco:
- Bitrot fuzzer em blocos .hrkb
- Torn Write simulator em .manifest
- Simulacao de ENOSPC (disco esgotado)
- Integracao com Storage Doctor / Verify
"""
from __future__ import annotations
import os
import random
import shutil
from pathlib import Path
from typing import Dict, List, Any
from src.adapters.cli_invoker import run_cli_verify

class StorageTamper:
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)

    def list_blocks(self) -> List[Path]:
        if not self.data_dir.exists():
            return []
        return list(self.data_dir.glob("**/*.hrkb"))

    def list_manifests(self) -> List[Path]:
        if not self.data_dir.exists():
            return []
        return list(self.data_dir.glob("**/*.manifest"))

    def inject_bitrot(self, block_path: Path, flip_count: int = 4) -> Dict[str, Any]:
        """Altera bits no payload do bloco preservando o magic header."""
        if not block_path.exists():
            return {"status": "SKIP", "reason": "block file does not exist"}
        size = block_path.stat().st_size
        if size < 64:
            return {"status": "SKIP", "reason": "block too small for bitrot"}

        offsets = random.sample(range(32, size), min(flip_count, size - 32))
        with open(block_path, "r+b") as f:
            for off in offsets:
                f.seek(off)
                b = f.read(1)[0]
                corrupted = b ^ (1 << random.randint(0, 7))
                f.seek(off)
                f.write(bytes([corrupted]))
        return {
            "status": "PASS",
            "file": str(block_path),
            "flipped_offsets": offsets,
            "size": size
        }

    def simulate_torn_write(self, manifest_path: Path) -> Dict[str, Any]:
        """Trunca o manifesto na metade para testar recuperacao consistente."""
        if not manifest_path.exists():
            return {"status": "SKIP", "reason": "manifest file does not exist"}
        size = manifest_path.stat().st_size
        if size <= 16:
            return {"status": "SKIP", "reason": "manifest too small"}

        cut = int(size * random.uniform(0.3, 0.7))
        backup = manifest_path.with_suffix(".manifest.bak")
        shutil.copyfile(manifest_path, backup)
        with open(manifest_path, "r+b") as f:
            f.truncate(cut)
        return {
            "status": "PASS",
            "manifest": str(manifest_path),
            "original_size": size,
            "truncated_size": cut,
            "backup": str(backup)
        }

    def verify_integrity(self, cli_binary: str) -> Dict[str, Any]:
        """Dispara heraclitus-cli verify isoladamente."""
        return run_cli_verify(cli_binary, str(self.data_dir))

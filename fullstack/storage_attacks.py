from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

MARKER = ".heraclitus-redteam-disposable"
CANDIDATE_SUFFIXES = {".hrkl", ".hrkb", ".hrkm", ".hrki", ".idx", ".manifest"}


def require_disposable(path: str | Path) -> Path:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"sandbox destrutiva inexistente: {root}")
    if not (root / MARKER).is_file():
        raise ValueError(f"sandbox destrutiva recusada: falta marcador {MARKER} em {root}")
    forbidden = {Path("/"), Path("/home"), Path("/var"), Path("/usr"), Path("/mnt"), Path("/mnt/data")}
    if root in forbidden or len(root.parts) < 3:
        raise ValueError(f"sandbox destrutiva perigosa demais: {root}")
    return root


def candidates(root: Path) -> list[Path]:
    rows = []
    for p in root.rglob("*"):
        if not p.is_file() or p.name == MARKER:
            continue
        lower = p.name.lower()
        if p.suffix.lower() in CANDIDATE_SUFFIXES or lower.startswith("manifest"):
            rows.append(p)
    return sorted(rows, key=lambda p: (p.stat().st_size, str(p)), reverse=True)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify(source_dir: str | Path, data_dir: Path, timeout: float) -> tuple[int | None, str]:
    argv = ["cargo", "run", "-q", "-p", "heraclitus-cli", "--", "storage", "doctor", str(data_dir)]
    try:
        cp = subprocess.run(argv, cwd=str(Path(source_dir).expanduser().resolve()), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, shell=False)
        return cp.returncode, cp.stdout[-3000:]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _mutate(lab, Result, source_dir: str, disposable: str, truncate: bool):
    root = require_disposable(disposable)
    aid = lab.attack_id("storage-truncate-v3" if truncate else "storage-bitrot-v3")
    rows = [p for p in candidates(root) if p.stat().st_size >= (256 if truncate else 64)]
    if not rows:
        result = Result(aid, "storage-truncation-detection" if truncate else "storage-bitrot-detection", str(root), "at least one physical storage candidate exists", "no eligible file", False, detail="UNVERIFIED: clone has no HRKL/HRKB/HRKM/HRKI candidate", severity="high", tags=["storage", "integrity"]); lab.report(result); return result
    target = rows[0]; backup = target.with_name(target.name + ".redteam.bak"); original_hash = sha256(target); shutil.copy2(target, backup)
    try:
        size = target.stat().st_size
        with target.open("r+b", buffering=0) as handle:
            if truncate:
                handle.truncate(max(1, size - max(1, min(128, size // 8))))
            else:
                offset = max(16, min(size - 1, size // 2)); handle.seek(offset); old = handle.read(1); handle.seek(offset); handle.write(bytes([old[0] ^ 0x01]))
            handle.flush(); os.fsync(handle.fileno())
        rc, output = _verify(source_dir, root, float(lab.cfg.get("storage_verify_timeout", 60)))
        detected = rc is not None and rc != 0
        result = Result(aid, "storage-truncation-detection" if truncate else "storage-bitrot-detection", str(target), "`heraclitus storage doctor` detects physical mutation", f"doctor_rc={rc}; target={target.name}", detected, blocked=detected, detail=output[-800:], severity="critical", tags=["storage", "integrity", "truncation" if truncate else "bitrot"]); lab.report(result); return result
    finally:
        shutil.move(str(backup), str(target))
        if sha256(target) != original_hash:
            raise RuntimeError(f"restauração SHA-256 falhou: {target}")


def run(lab, Result, source_dir: str, disposable: str):
    return [_mutate(lab, Result, source_dir, disposable, False), _mutate(lab, Result, source_dir, disposable, True)]

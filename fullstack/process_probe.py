from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class ProcessSnapshot:
    pid: int
    rss_kb: int | None = None
    vm_kb: int | None = None
    threads: int | None = None
    fds: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def snapshot(pid: int | None) -> ProcessSnapshot | None:
    if pid is None or pid <= 0:
        return None
    root = Path(f"/proc/{pid}")
    out = ProcessSnapshot(pid=pid)
    if not root.exists():
        return out
    try:
        for line in (root / "status").read_text(errors="replace").splitlines():
            if line.startswith("VmRSS:"):
                out.rss_kb = int(line.split()[1])
            elif line.startswith("VmSize:"):
                out.vm_kb = int(line.split()[1])
            elif line.startswith("Threads:"):
                out.threads = int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    try:
        out.fds = len(list((root / "fd").iterdir()))
    except OSError:
        pass
    return out


def delta(before: ProcessSnapshot | None, after: ProcessSnapshot | None) -> dict[str, int | None]:
    names = ("rss_kb", "vm_kb", "threads", "fds")
    if before is None or after is None:
        return {name: None for name in names}
    result: dict[str, int | None] = {}
    for name in names:
        a, b = getattr(before, name), getattr(after, name)
        result[name] = None if a is None or b is None else b - a
    return result

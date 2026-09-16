from __future__ import annotations
from dataclasses import asdict,dataclass
from pathlib import Path
@dataclass
class ProcessSnapshot:
    pid:int; rss_kb:int|None=None; vm_kb:int|None=None; threads:int|None=None; fds:int|None=None
    def to_dict(self): return asdict(self)
def snapshot(pid):
    if not pid or pid<=0:return None
    root=Path(f"/proc/{pid}"); out=ProcessSnapshot(pid)
    if not root.exists():return out
    try:
        for line in (root/"status").read_text(errors="replace").splitlines():
            if line.startswith("VmRSS:"):out.rss_kb=int(line.split()[1])
            elif line.startswith("VmSize:"):out.vm_kb=int(line.split()[1])
            elif line.startswith("Threads:"):out.threads=int(line.split()[1])
    except Exception:pass
    try:out.fds=len(list((root/"fd").iterdir()))
    except Exception:pass
    return out
def delta(before,after):
    if before is None or after is None:return {"rss_kb":None,"vm_kb":None,"threads":None,"fds":None}
    return {n:(None if getattr(before,n) is None or getattr(after,n) is None else getattr(after,n)-getattr(before,n)) for n in ("rss_kb","vm_kb","threads","fds")}

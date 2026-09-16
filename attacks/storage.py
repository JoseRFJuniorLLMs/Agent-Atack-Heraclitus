from __future__ import annotations
import hashlib,os,shutil,subprocess
from pathlib import Path
from .common import AttackResult
MARKER=".heraclitus-redteam-disposable"; CANDIDATE_SUFFIXES={".hrkl",".hrkb",".manifest",".idx"}
def require_disposable(path):
    root=Path(path).expanduser().resolve()
    if not root.is_dir():raise ValueError(f"sandbox destrutiva inexistente: {root}")
    if not (root/MARKER).is_file():raise ValueError(f"sandbox destrutiva recusada: falta marcador {MARKER} em {root}")
    if str(root) in {"/","/home","/var","/usr","/mnt","/mnt/data"} or len(root.parts)<3:raise ValueError(f"sandbox destrutiva perigosa demais: {root}")
    return root
def _files(root):return sorted([p for p in root.rglob("*") if p.is_file() and p.name!=MARKER and (p.suffix.lower() in CANDIDATE_SUFFIXES or p.name.lower().startswith("manifest"))],key=lambda p:(p.stat().st_size,str(p)),reverse=True)
def _sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()
def _run_verify(ctx,root):
    cmd=ctx.cfg.get("verify_command")
    if not isinstance(cmd,list) or not cmd or not all(isinstance(x,str) for x in cmd):return None,"verify_command ausente/inválido"
    argv=[x.replace("{data_dir}",str(root)) for x in cmd]
    try:
        cp=subprocess.run(argv,cwd=ctx.cfg.get("source_dir") or None,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=float(ctx.cfg.get("verify_timeout",30)),shell=False);return cp.returncode,cp.stdout[-2000:]
    except (OSError,subprocess.TimeoutExpired) as exc:return None,f"{type(exc).__name__}: {exc}"
def _mutate(ctx,disposable,truncate=False):
    root=require_disposable(disposable); aid=ctx.attack_id("storage-truncate" if truncate else "storage-bitrot"); candidates=[p for p in _files(root) if p.stat().st_size>=(256 if truncate else 64)]
    if not candidates:return ctx.record(AttackResult(aid,"storage-truncation-detection" if truncate else "storage-bitrot-detection","storage",str(root),"eligible storage file exists","no candidate file",False,"high",detail="UNVERIFIED",tags=["storage"]),native_probe=False)
    target=candidates[0]; backup=target.with_name(target.name+".redteam.bak"); shutil.copy2(target,backup); original=_sha(target)
    try:
        size=target.stat().st_size
        with target.open("r+b",buffering=0) as f:
            if truncate:cut=max(1,min(128,size//8));f.truncate(size-cut)
            else:
                offset=max(16,min(size-1,size//2));f.seek(offset);old=f.read(1);f.seek(offset);f.write(bytes([old[0]^1]))
            f.flush();os.fsync(f.fileno())
        rc,out=_run_verify(ctx,root); detected=rc is not None and rc!=0; observed=f"verify_rc={rc}; target={target.name}"
        return ctx.record(AttackResult(aid,"storage-truncation-detection" if truncate else "storage-bitrot-detection","storage",str(target),"doctor/verify rejects physical mutation",observed,detected,"critical",blocked=detected,detail=out[-600:],tags=["storage","integrity","torn-write" if truncate else "bitrot"]),native_probe=False)
    finally:
        shutil.move(str(backup),str(target))
        if _sha(target)!=original:raise RuntimeError(f"restauração falhou: {target}")
def bitrot_detection(ctx,disposable):return _mutate(ctx,disposable,False)
def truncation_detection(ctx,disposable):return _mutate(ctx,disposable,True)
def run(ctx,disposable):return [bitrot_detection(ctx,disposable),truncation_detection(ctx,disposable)]

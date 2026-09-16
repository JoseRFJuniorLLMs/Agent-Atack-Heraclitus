from __future__ import annotations
import os,subprocess,time
from dataclasses import dataclass
from pathlib import Path
from .common import AttackResult
@dataclass(frozen=True)
class SourceProbe: vector:str;category:str;crate:str;args:tuple[str,...];detail:str;severity:str="high"
PROBES=[
SourceProbe("raft-adversarial-consensus","raft","heraclitus-raft",("test","-p","heraclitus-raft","--features","replication","--","--nocapture"),"Runs cuttable-link/quorum/failover/snapshot consensus suite."),
SourceProbe("ebr-concurrency","memory","heraclitus-core",("test","-p","heraclitus-core","ebr","--","--nocapture"),"EBR pin/reclaim invariants."),
SourceProbe("hlc-monotonicity","clock","heraclitus-core",("test","-p","heraclitus-core","hlc","--","--nocapture"),"HLC monotonicity with synthetic timestamps."),
SourceProbe("log-v6-integrity","storage","heraclitus-log",("test","-p","heraclitus-log","v6","--","--nocapture"),"V6 decoder/CRC/recovery/packer integrity."),
SourceProbe("compliance-rfc3161","compliance","heraclitus-compliance",("test","-p","heraclitus-compliance","rfc3161","--","--nocapture"),"Timestamp token/DER path."),
SourceProbe("receipt-merkle","compliance","heraclitus-compliance",("test","-p","heraclitus-compliance","receipt","--","--nocapture"),"Receipt/Merkle invariants."),
SourceProbe("hnsw-degenerate-input","index","heraclitus-index-vector",("test","-p","heraclitus-index-vector","--","--nocapture"),"Vector-index topology/recall behavior."),
SourceProbe("graph-temporal-cycles","index","heraclitus-index-graph",("test","-p","heraclitus-index-graph","temporal","--","--nocapture"),"Temporal traversal cycle/termination."),
SourceProbe("hume-ir-invalid-state","query","hume-ir",("test","-p","hume-ir","--","--nocapture"),"IR verifier/JIT-facing state validation."),
SourceProbe("hume-kernel-bounds","query","hume-kernel",("test","-p","hume-kernel","--","--nocapture"),"Kernel execution bounds."),]
def run_probe(ctx,root,p,timeout):
    aid=ctx.attack_id(p.vector);started=time.perf_counter()
    try:
        cp=subprocess.run(["cargo",*p.args],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout,shell=False);passed=cp.returncode==0;observed=f"cargo rc={cp.returncode}";detail=(p.detail+"\n"+cp.stdout[-1200:]).strip()
    except subprocess.TimeoutExpired:passed=False;observed="timeout";detail=p.detail+f"\nTIMEOUT after {timeout}s"
    except OSError as exc:passed=False;observed="unverified";detail=p.detail+f"\n{type(exc).__name__}: {exc}"
    return ctx.record(AttackResult(aid,p.vector,p.category,f"source:{p.crate}","adversarial/source invariant suite passes",observed,passed,p.severity,duration_ms=(time.perf_counter()-started)*1000,detail=detail,tags=["source",p.crate]),native_probe=False)
def run(ctx,source_dir):
    root=Path(source_dir).expanduser().resolve()
    if not (root/"Cargo.toml").is_file():return [ctx.record(AttackResult(ctx.attack_id("source-root"),"source-tree-available","source",str(root),"HeraclitusDB Cargo workspace exists","workspace unavailable",False,detail="Use --source-dir /path/to/HeraclitusDB",tags=["source","unverified"]),native_probe=False)]
    return [run_probe(ctx,root,p,float(ctx.cfg.get("source_probe_timeout",180))) for p in PROBES]

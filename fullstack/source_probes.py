from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Probe:
    vector: str
    target: str
    cargo_args: tuple[str, ...]
    detail: str
    severity: str = "high"


PROBES = (
    Probe("raft-consensus-adversarial-suite", "source:heraclitus-raft", ("test", "-p", "heraclitus-raft", "--features", "replication", "--", "--nocapture"), "Quorum/failover/partition/snapshot/restart suite with replication enabled.", "critical"),
    Probe("ebr-concurrency-suite", "source:heraclitus-core", ("test", "-p", "heraclitus-core", "ebr", "--", "--nocapture"), "EBR pin/reclaim invariants."),
    Probe("hlc-monotonicity-suite", "source:heraclitus-core", ("test", "-p", "heraclitus-core", "hlc", "--", "--nocapture"), "HLC monotonicity using synthetic clock/state tests."),
    Probe("log-v6-integrity-suite", "source:heraclitus-log", ("test", "-p", "heraclitus-log", "v6", "--", "--nocapture"), "Decoder/CRC/recovery/packer v6 tests.", "critical"),
    Probe("compliance-rfc3161-suite", "source:heraclitus-compliance", ("test", "-p", "heraclitus-compliance", "rfc3161", "--", "--nocapture"), "RFC3161/DER path."),
    Probe("compliance-receipt-merkle-suite", "source:heraclitus-compliance", ("test", "-p", "heraclitus-compliance", "receipt", "--", "--nocapture"), "Receipt/Merkle integrity."),
    Probe("hnsw-adversarial-input-suite", "source:heraclitus-index-vector", ("test", "-p", "heraclitus-index-vector", "--", "--nocapture"), "HNSW topology/recall and vector bounds."),
    Probe("temporal-graph-cycle-suite", "source:heraclitus-index-graph", ("test", "-p", "heraclitus-index-graph", "temporal", "--", "--nocapture"), "Temporal traversal cycle/termination tests."),
    Probe("hume-ir-validation-suite", "source:hume-ir", ("test", "-p", "hume-ir", "--", "--nocapture"), "IR validation and malformed-state rejection."),
    Probe("hume-kernel-bounds-suite", "source:hume-kernel", ("test", "-p", "hume-kernel", "--", "--nocapture"), "Kernel execution bounds and vectorized execution tests."),
)


def run_one(lab, Result, root: Path, probe: Probe, timeout: float):
    aid = lab.attack_id(probe.vector); started = time.perf_counter()
    try:
        cp = subprocess.run(["cargo", *probe.cargo_args], cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, shell=False)
        passed = cp.returncode == 0; observed = f"cargo rc={cp.returncode}"; detail = f"{probe.detail}\n{cp.stdout[-1600:]}"
    except subprocess.TimeoutExpired as exc:
        passed = False; observed = "timeout"; detail = f"{probe.detail}\nTIMEOUT after {timeout}s; {(exc.stdout or '')[-500:] if isinstance(exc.stdout, str) else ''}"
    except OSError as exc:
        passed = False; observed = "unverified"; detail = f"{probe.detail}\n{type(exc).__name__}: {exc}"
    result = Result(aid, probe.vector, probe.target, "adversarial source invariant suite passes", observed, passed, detail=detail, duration_ms=(time.perf_counter() - started) * 1000, severity=probe.severity, tags=["source", "recursive-audit"]); lab.report(result); return result


def run(lab, Result, source_dir: str):
    root = Path(source_dir).expanduser().resolve()
    if not (root / "Cargo.toml").is_file():
        result = Result(lab.attack_id("source-root-v3"), "source-tree-available", str(root), "HeraclitusDB Cargo workspace exists", "workspace unavailable", False, detail="Use --source-dir /path/to/HeraclitusDB", severity="high", tags=["source", "unverified"]); lab.report(result); return [result]
    timeout = float(lab.cfg.get("source_probe_timeout", 300))
    return [run_one(lab, Result, root, probe, timeout) for probe in PROBES]

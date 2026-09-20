#!/usr/bin/env python3
"""Full-stack V3 extension for Agent-Atack-Heraclitus."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

import runner
from runner_v3 import AdvancedLab
from fullstack import protocol_attacks, resource_attacks, source_probes, storage_attacks
from fullstack.junit_report import write as write_junit
from fullstack.process_probe import snapshot

VERSION = "3.1.0-fullstack"


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Agent-Atack-Heraclitus V3 full-stack, loopback-only")
    parser.add_argument("--config", default="config.example.json")
    parser.add_argument("--profile", choices=sorted(runner.PROFILES), default="full")
    parser.add_argument("--suite", choices=["edge", "resource", "source", "destructive", "all"], default="edge")
    parser.add_argument("--source-dir"); parser.add_argument("--destructive-sandbox"); parser.add_argument("--server-pid", type=int)
    parser.add_argument("--report-dir", default="reports/fullstack-latest")
    parser.add_argument("--agents", type=int, default=None); parser.add_argument("--iterations", type=int, default=None); parser.add_argument("--concurrency", type=int, default=None)
    args = parser.parse_args(); cfg = load(args.config); lab = AdvancedLab(cfg, args.profile, args)
    print(f"Agent-Atack-Heraclitus v{VERSION} campaign={lab.campaign} LOOPBACK-ONLY suite={args.suite}")
    before = snapshot(args.server_pid)
    if args.suite in {"edge", "all"}:
        lab.run(); protocol_attacks.fragmented_chunked_exec(lab, runner.Result); protocol_attacks.partial_body_drop(lab, runner.Result)
    if args.suite in {"resource", "all"}:
        resource_attacks.bounded_slow_connections(lab, runner.Result, args.server_pid); resource_attacks.connection_churn(lab, runner.Result, args.server_pid)
    if args.suite in {"source", "all"}:
        if not args.source_dir: raise SystemExit("--source-dir é obrigatório para suite source/all")
        source_probes.run(lab, runner.Result, args.source_dir)
    if args.suite in {"destructive", "all"}:
        if not args.source_dir or not args.destructive_sandbox: raise SystemExit("--source-dir e --destructive-sandbox são obrigatórios para destructive/all")
        storage_attacks.run(lab, runner.Result, args.source_dir, args.destructive_sandbox)
    after = snapshot(args.server_pid); report_dir = Path(args.report_dir); report_dir.mkdir(parents=True, exist_ok=True)
    summary = {"total": len(lab.results), "passed": sum(r.passed for r in lab.results if not r.skipped), "failed": sum((not r.passed) for r in lab.results if not r.skipped), "skipped": sum(r.skipped for r in lab.results), "evidence_lsn": sum(r.evidence_lsn is not None for r in lab.results)}
    document = {"product": "Agent-Atack-Heraclitus", "version": VERSION, "campaign": lab.campaign, "profile": args.profile, "suite": args.suite, "loopback_only": True, "server_before": before.to_dict() if before else None, "server_after": after.to_dict() if after else None, "summary": summary, "results": [asdict(r) for r in lab.results]}
    (report_dir / "report.json").write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    (report_dir / "report.md").write_text(runner.markdown_report("Agent-Atack-Heraclitus V3 Full-Stack", lab.campaign, args.profile, lab.results), encoding="utf-8")
    write_junit(report_dir / "junit.xml", lab.campaign, lab.results)
    print(f"FULLSTACK SUMMARY pass={summary['passed']} fail={summary['failed']} skip={summary['skipped']} reports={report_dir}")
    return 0 if summary["failed"] == 0 else 2


if __name__ == "__main__": raise SystemExit(main())

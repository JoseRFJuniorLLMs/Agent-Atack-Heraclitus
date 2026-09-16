#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
from attacks.common import AttackResult,LabContext
from attacks import gateway,protocol,resource,source,storage
from metrics.process_probe import snapshot
from reporting import write_json,write_junit,write_markdown
def load_config(path):
    data=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data,dict):raise SystemExit("config precisa ser objeto JSON")
    return data
def preflight(ctx):
    out=[]
    for label,base,path in [("agent-api",ctx.cfg.get("agent_api"),"/api/v1/agent/status"),("core-rest",ctx.cfg.get("core_rest"),"/stats")]:
        if not base:continue
        h=ctx.auth_agent() if label=="agent-api" else ctx.core_auth(True);s,_,ms=ctx.request(str(base),path,headers=h);out.append(ctx.record(AttackResult(ctx.attack_id(f"preflight-{label}"),f"preflight-{label}","preflight",str(base),"HTTP 200",f"HTTP {s}",s==200,status=s,duration_ms=ms,tags=["preflight"]),native_probe=False))
    hits=ctx.hits();out.append(ctx.record(AttackResult(ctx.attack_id("preflight-upstream"),"preflight-upstream","preflight",str(ctx.cfg.get("upstream_hits")),"upstream counter reachable",f"hits={hits}",hits is not None,detail="safe stub recommended",tags=["preflight"]),native_probe=False));return out
def edge(ctx):
    out=[];out.extend(gateway.unicode_policy_evasion(ctx));out.extend(gateway.method_header_mismatch(ctx));out.append(gateway.same_session_reentrancy(ctx));out.append(gateway.approval_exact_once_race(ctx));out.extend(protocol.run(ctx));return out
def stress(ctx,pid):
    out=[gateway.multi_agent_campaign(ctx),gateway.policy_reload_race(ctx)];out.extend(resource.run(ctx,pid));return out
def main():
    p=argparse.ArgumentParser(description="Agent-Atack-Heraclitus V3, adversarial qualification harness, loopback-only");p.add_argument("config",nargs="?",default="config.example.json");p.add_argument("--suite",choices=["edge","stress","source","destructive","all"],default="edge");p.add_argument("--stress",action="store_true");p.add_argument("--destructive-sandbox");p.add_argument("--source-dir");p.add_argument("--server-pid",type=int);p.add_argument("--report-dir",default="reports/latest");args=p.parse_args();cfg=load_config(args.config)
    if args.source_dir:cfg["source_dir"]=args.source_dir
    ctx=LabContext(cfg);print(f"Agent-Atack-Heraclitus V3 campaign={ctx.campaign} LOOPBACK-ONLY suite={args.suite}");preflight(ctx);before=snapshot(args.server_pid)
    if args.suite in {"edge","all"}:edge(ctx)
    if args.suite in {"stress","all"}:
        if not args.stress:print("[SKIP] stress suite requires --stress",file=sys.stderr)
        else:stress(ctx,args.server_pid)
    if args.suite in {"source","all"}:
        if not args.source_dir:print("[SKIP] source suite requires --source-dir",file=sys.stderr)
        else:source.run(ctx,args.source_dir)
    if args.suite in {"destructive","all"}:
        if not args.destructive_sandbox:print("[SKIP] destructive suite requires --destructive-sandbox",file=sys.stderr)
        else:storage.run(ctx,args.destructive_sandbox)
    after=snapshot(args.server_pid);rd=Path(args.report_dir);rd.mkdir(parents=True,exist_ok=True);meta={"suite":args.suite,"loopback_only":True,"server_before":before.to_dict() if before else None,"server_after":after.to_dict() if after else None};write_json(rd/"report.json",ctx.campaign,ctx.results,meta);write_markdown(rd/"report.md",ctx.campaign,ctx.results,meta);write_junit(rd/"junit.xml",ctx.campaign,ctx.results);failures=sum(not r.passed for r in ctx.results);print(f"V3 complete: total={len(ctx.results)} pass={len(ctx.results)-failures} fail={failures} reports={rd}");return 1 if failures else 0
if __name__=="__main__":raise SystemExit(main())

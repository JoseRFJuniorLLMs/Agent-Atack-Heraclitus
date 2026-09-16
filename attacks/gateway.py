from __future__ import annotations
import concurrent.futures, json, threading
from typing import Any
from .common import AttackResult, LabContext

def unicode_policy_evasion(ctx):
    variants=[("zero-width","ex\u200bec"),("fullwidth","ｅｘｅｃ"),("cyrillic-e","еxec"),("combining","e\u0338xec"),("rtl-mark","ex\u200fec")]; out=[]
    for label,tool_name in variants:
        aid=ctx.attack_id(f"unicode-{label}"); agent=f"v3-unicode-{label}"; before=ctx.hits(); s,b,ms=ctx.request(str(ctx.cfg["mcp_gateway"]),"/mcp","POST",ctx.tool(aid,tool_name,{"command":"echo SAFE_MARKER"}),ctx.mcp_headers(agent,aid)); after=ctx.hits(); delta=None if before is None or after is None else after-before; passed=s in {400,401,403,404,405,422} and delta in {0,None}
        out.append(ctx.record(AttackResult(aid,f"unicode-homograph-{label}","policy","mcp:tool-name","variant restricted/unknown rejected and upstreamΔ=0",f"HTTP {s}",passed,"high",s,passed,delta,duration_ms=ms,agent_id=agent,detail=ctx.reason(b) or tool_name.encode("unicode_escape").decode(),tags=["unicode","policy-bypass"])))
    return out

def method_header_mismatch(ctx):
    cases=[("body-tool-header-resource","resources/read",ctx.tool("placeholder","exec",{"command":"echo SAFE"})),("body-resource-header-tool","tools/call",{"jsonrpc":"2.0","id":"placeholder","method":"resources/read","params":{"uri":"lab://safe"}})]; out=[]
    for label,header_method,body in cases:
        aid=ctx.attack_id(label); body=json.loads(json.dumps(body)); body["id"]=aid; before=ctx.hits(); s,resp,ms=ctx.request(str(ctx.cfg["mcp_gateway"]),"/mcp","POST",body,ctx.mcp_headers(f"v3-{label}",aid,header_method)); after=ctx.hits(); delta=None if before is None or after is None else after-before; dangerous=body.get("method")=="tools/call" and body.get("params",{}).get("name")=="exec"; passed=(not dangerous) or (s in {400,401,403,422} and delta in {0,None})
        out.append(ctx.record(AttackResult(aid,f"mcp-method-mismatch-{label}","gateway","mcp:/mcp","body semantics win; dangerous tools/call cannot hide behind header",f"HTTP {s}",passed,"high",s,s in {400,401,403,422},delta,duration_ms=ms,agent_id=f"v3-{label}",detail=ctx.reason(resp) or "header/body mismatch",tags=["parser-differential","mcp"])))
    return out

def same_session_reentrancy(ctx):
    aid=ctx.attack_id("reentrancy"); run=f"run-{aid}"; before=ctx.hits(); n=int(ctx.cfg.get("reentrancy_calls",32))
    def one(i):
        req=ctx.tool(f"{aid}-{i}","exec",{"command":"echo SAFE_MARKER","seq":i}) if i%2 else ctx.tool(f"{aid}-{i}","lookup_vendor",{"vendor":f"synthetic-{i}"}); return i,ctx.request(str(ctx.cfg["mcp_gateway"]),"/mcp","POST",req,ctx.mcp_headers(f"reentrant-{i%4}",run),timeout=8)[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32,n)) as p: rows=list(p.map(one,range(n)))
    after=ctx.hits(); delta=None if before is None or after is None else after-before; allowed=sum(1 for i,_ in rows if i%2==0); denied=sum(1 for i,s in rows if i%2==1 and s==403); expected=n//2; passed=denied==expected and (delta is None or delta<=allowed)
    return ctx.record(AttackResult(aid,"same-session-reentrancy","gateway","mcp:shared-run",f"all {expected} restricted calls denied; no extra upstream effect",f"restricted-denied={denied}/{expected}; upstreamΔ={delta}",passed,"critical",403 if denied else None,passed,delta,agent_id="multi",detail=f"{n} interleaved calls share run/session",tags=["reentrancy","race"]))

def policy_reload_race(ctx):
    aid=ctx.attack_id("policy-reload-race"); n=int(ctx.cfg.get("policy_race_calls",48)); before=ctx.hits(); stop=threading.Event(); acts=[]
    def reload_loop():
        docs=['version: "agent-policy-v999"\n','id: x\nrules: [\n','version: []\nid: bad\n']; j=0
        while not stop.is_set() and j<16:
            s,_,_=ctx.request(str(ctx.cfg["agent_api"]),"/api/v1/agent/policies/activate","POST",{"document":docs[j%len(docs)]},ctx.auth_agent(),timeout=2); acts.append(s); j+=1
    t=threading.Thread(target=reload_loop,daemon=True); t.start()
    def deny(i): return ctx.request(str(ctx.cfg["mcp_gateway"]),"/mcp","POST",ctx.tool(f"{aid}-{i}","exec",{"command":"echo SAFE_MARKER","race":i}),ctx.mcp_headers(f"race-{i%8}",aid),timeout=5)[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as p: sts=list(p.map(deny,range(n)))
    stop.set(); t.join(timeout=2); after=ctx.hits(); delta=None if before is None or after is None else after-before; denied=sum(s==403 for s in sts); reload_ok=all(s in {400,401,403,409,422,None} for s in acts); passed=denied==n and delta in {0,None} and reload_ok
    return ctx.record(AttackResult(aid,"policy-hot-reload-race","policy","mcp+policy-api",f"{n}/{n} restricted calls denied while invalid policies race",f"denied={denied}/{n}; reloads={len(acts)}",passed,"critical",403 if denied else None,passed,delta,agent_id="multi",detail=f"reload statuses={sorted(set(str(x) for x in acts))}",tags=["policy","race","hot-reload"]))

def approval_exact_once_race(ctx):
    aid=ctx.attack_id("approval-race"); req=ctx.tool(aid,"send_payment",{"amount":75000,"account":"synthetic-v3-race"}); s,b,_=ctx.request(str(ctx.cfg["mcp_gateway"]),"/mcp","POST",req,ctx.mcp_headers("approval-racer",aid))
    try: approval=b["error"]["data"]["heraclitus"]["approval_id"]
    except Exception: approval=None
    if s!=202 or not approval: return ctx.record(AttackResult(aid,"approval-exact-once-race","approval","mcp:send_payment","approval pending before race",f"HTTP {s}",False,"critical",s,True,agent_id="approval-racer",detail="approval_id unavailable",tags=["approval","race"]))
    astatus,_,_=ctx.request(str(ctx.cfg["agent_api"]),f"/api/v1/agent/approvals/{approval}/approve","POST",{},ctx.auth_agent()); racers=int(ctx.cfg.get("approval_racers",16)); before=ctx.hits(); barrier=threading.Barrier(racers)
    def retry(i):
        try: barrier.wait(timeout=3)
        except Exception: pass
        return ctx.request(str(ctx.cfg["mcp_gateway"]),"/mcp","POST",req,ctx.mcp_headers(f"approval-retry-{i}",aid),timeout=8)[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=racers) as p: sts=list(p.map(retry,range(racers)))
    after=ctx.hits(); delta=None if before is None or after is None else after-before; successful=sum(x==200 for x in sts); passed=astatus==200 and successful==1 and delta in {1,None}
    return ctx.record(AttackResult(aid,"approval-exact-once-race","approval","mcp:send_payment","exactly one retry executes after one approval",f"approve={astatus}; success={successful}/{racers}; upstreamΔ={delta}",passed,"critical",200 if successful else None,passed,delta,agent_id="multi",detail=f"statuses={dict((str(x),sts.count(x)) for x in set(sts))}",tags=["approval","exact-once","race"]))

def multi_agent_campaign(ctx):
    agents=max(2,int(ctx.cfg.get("agents",12))); iterations=max(1,int(ctx.cfg.get("iterations",3))); aid=ctx.attack_id("multi-agent"); before=ctx.hits(); cases=[(a,i,(a+i)%3) for a in range(agents) for i in range(iterations)]
    def act(row):
        a,i,kind=row; agent=f"agent-{a:03d}"; rid=f"{aid}-{a}-{i}"
        if kind==0: req=ctx.tool(rid,"exec",{"command":"echo SAFE_MARKER","agent":a}); expected="deny"
        elif kind==1: req=ctx.tool(rid,"lookup_vendor",{"vendor":f"synthetic-{a}-{i}"}); expected="allow"
        else: req=ctx.tool(rid,"send_payment",{"amount":75000+i,"account":f"synthetic-{a}"}); expected="approval"
        return expected,ctx.request(str(ctx.cfg["mcp_gateway"]),"/mcp","POST",req,ctx.mcp_headers(agent,rid),timeout=8)[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,min(int(ctx.cfg.get("concurrency",24)),len(cases),64))) as p: rows=list(p.map(act,cases))
    after=ctx.hits(); delta=None if before is None or after is None else after-before; deny_bad=sum(1 for e,s in rows if e=="deny" and s!=403); allow_bad=sum(1 for e,s in rows if e=="allow" and s!=200); approval_bad=sum(1 for e,s in rows if e=="approval" and s!=202); expected_allows=sum(1 for e,_ in rows if e=="allow"); passed=deny_bad==allow_bad==approval_bad==0 and (delta is None or delta==expected_allows)
    return ctx.record(AttackResult(aid,"multi-agent-mixed-campaign","campaign","mcp:/mcp","deny/allow/approval remain isolated per agent",f"calls={len(rows)} deny_bad={deny_bad} allow_bad={allow_bad} approval_bad={approval_bad}",passed,"critical",blocked=passed,upstream_delta=delta,agent_id=f"{agents} agents",detail=f"expected benign upstream effects={expected_allows}",tags=["multi-agent","concurrency","isolation"]),native_probe=False)

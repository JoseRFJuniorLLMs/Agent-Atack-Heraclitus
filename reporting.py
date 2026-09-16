from __future__ import annotations
import json
from xml.etree.ElementTree import Element,SubElement,ElementTree
def summary(results):return {"total":len(results),"passed":sum(r.passed for r in results),"failed":sum(not r.passed for r in results),"native_observability_missing":sum(r.native_evidence is False for r in results)}
def write_json(path,campaign,results,extra=None):
    doc={"schema":"agent-atack-heraclitus-v3","campaign":campaign,"summary":summary(results),"results":[r.to_dict() for r in results]};
    if extra:doc["meta"]=extra
    path.write_text(json.dumps(doc,ensure_ascii=False,indent=2),encoding="utf-8")
def write_markdown(path,campaign,results,extra=None):
    s=summary(results);lines=[f"# Agent-Atack-Heraclitus V3 · {campaign}","",f"- Total: **{s['total']}**",f"- PASS: **{s['passed']}**",f"- FAIL: **{s['failed']}**",f"- Native evidence not found: **{s['native_observability_missing']}**","","| Estado | Categoria | Vetor | Observado | Upstream Δ | Native evidence |","|---|---|---|---|---:|---|"]
    for r in results:lines.append(f"| {'PASS' if r.passed else 'FAIL'} | {r.category} | `{r.vector}` | {r.observed.replace('|','/')} | {'' if r.upstream_delta is None else r.upstream_delta} | {r.native_evidence} |")
    if extra:lines += ["","## Metadados","","```json",json.dumps(extra,ensure_ascii=False,indent=2),"```"]
    path.write_text("\n".join(lines)+"\n",encoding="utf-8")
def write_junit(path,campaign,results):
    s=summary(results);suite=Element("testsuite",name=f"Agent-Atack-Heraclitus-V3:{campaign}",tests=str(s["total"]),failures=str(s["failed"]))
    for r in results:
        case=SubElement(suite,"testcase",classname=r.category,name=r.vector,time=f"{r.duration_ms/1000:.6f}")
        if not r.passed:SubElement(case,"failure",message=r.observed).text=r.detail
        props=SubElement(case,"properties")
        for k,v in {"attack_id":r.attack_id,"target":r.target,"upstream_delta":r.upstream_delta,"native_evidence":r.native_evidence}.items():SubElement(props,"property",name=k,value=str(v))
    ElementTree(suite).write(path,encoding="utf-8",xml_declaration=True)

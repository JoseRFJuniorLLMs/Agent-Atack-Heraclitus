from __future__ import annotations

from xml.etree.ElementTree import Element, ElementTree, SubElement


def write(path, campaign: str, results) -> None:
    active = [r for r in results if not getattr(r, "skipped", False)]
    failed = sum(not r.passed for r in active); skipped = sum(bool(getattr(r, "skipped", False)) for r in results)
    suite = Element("testsuite", name=f"Agent-Atack-Heraclitus:{campaign}", tests=str(len(results)), failures=str(failed), skipped=str(skipped))
    for r in results:
        case = SubElement(suite, "testcase", classname="fullstack-redteam", name=r.vector, time=f"{getattr(r, 'duration_ms', 0.0) / 1000:.6f}")
        if getattr(r, "skipped", False): SubElement(case, "skipped").text = getattr(r, "detail", "")
        elif not r.passed: SubElement(case, "failure", message=r.result).text = r.detail
        props = SubElement(case, "properties")
        for key, value in {"attack_id": r.attack_id, "target": r.target, "severity": getattr(r, "severity", ""), "upstream_delta": getattr(r, "upstream_delta", None), "evidence_lsn": getattr(r, "evidence_lsn", None)}.items():
            SubElement(props, "property", name=key, value=str(value))
    ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)

"""Render pipeline results as JSON-ready dicts and Markdown."""

from typing import Any, Dict, List

from ai_security_review.scans import SCAN_DEFINITIONS, SCAN_ORDER

SEVERITY_ICON = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}


def finding_comment_body(f: Dict[str, Any]) -> str:
    scans = ", ".join(f.get("scans") or [f.get("scan", "")])
    meta = f"**Category:** `{f['category']}` · **Found by:** {scans} · **Confidence:** {f['confidence']:.2f}"
    if f.get("rule_id"):
        meta += f" · **Rule:** `{f['rule_id']}`"
    lines = [
        f"**{SEVERITY_ICON.get(f['severity'], '')} {f['severity']}: {f['title']}**",
        "",
        meta,
        "",
        f["description"],
    ]
    if f.get("exploit_scenario"):
        lines += ["", f"**Exploit scenario:** {f['exploit_scenario']}"]
    if f.get("recommendation"):
        lines += ["", f"**Recommendation:** {f['recommendation']}"]
    if not f.get("introduced_by_change", True):
        lines += ["", "_Pre-existing code made newly reachable by this change._"]
    return "\n".join(lines)


def render_markdown_summary(result: Dict[str, Any]) -> str:
    triage = result.get("triage") or {}
    findings: List[Dict[str, Any]] = result.get("findings") or []
    counts = result.get("severity_counts") or {}
    scan_results = {s["scan"]: s for s in result.get("scan_results") or []}

    out: List[str] = ["## 🛡️ AI Security Review", ""]
    if result.get("error"):
        out += [f"> ⚠️ The review did not complete: {result['error']}", ""]

    out += ["### Triage", ""]
    if triage.get("skipped"):
        out.append("_Triage skipped; scans were selected explicitly._")
    else:
        out.append(f"**Risk level:** {str(triage.get('risk_level', 'unknown')).upper()} · **Change kind:** {triage.get('change_kind', 'unknown')}")
        out.append("")
        out.append(triage.get("summary", ""))
    out.append("")
    out.append("| Scan | Selected | Confidence | Reason |")
    out.append("|---|---|---|---|")
    for key in SCAN_ORDER:
        entry = (triage.get("scans") or {}).get(key) or {}
        selected = key in (triage.get("selected_scans") or [])
        status = scan_results.get(key, {}).get("status")
        mark = "✅ ran" if selected and status == "completed" else ("❌ failed" if selected and status == "failed" else ("✅ selected" if selected else "— skipped"))
        reason = str(entry.get("reason", "")).replace("|", "\\|")
        out.append(f"| {SCAN_DEFINITIONS[key].title} | {mark} | {float(entry.get('confidence', 0)):.2f} | {reason} |")
    out.append("")

    tools = result.get("tool_results") or []
    if tools:
        out += ["### Scanners", "", "| Tool | Status | Version | Findings | Candidates | Notes |", "|---|---|---|---|---|---|"]
        for t in tools:
            status = {"completed": "✅ ran", "skipped": "— skipped", "failed": "❌ failed"}.get(t.get("status"), t.get("status", ""))
            note = str(t.get("error") or t.get("notes") or "").replace("|", "\\|")[:160]
            out.append(f"| {t.get('tool')} | {status} | {t.get('version') or ''} | {t.get('findings_count', 0)} | {t.get('candidates_count', 0)} | {note} |")
        out.append("")

    out += ["### Findings", ""]
    if not findings:
        if triage.get("selected_scans"):
            out.append("No findings met the reporting bar.")
        else:
            out.append("No scans were needed for this change.")
    else:
        out.append(f"**{len(findings)}** finding(s): {counts.get('HIGH', 0)} high · {counts.get('MEDIUM', 0)} medium · {counts.get('LOW', 0)} low")
        out.append("")
        for f in findings:
            out.append(f"<details><summary>{SEVERITY_ICON.get(f['severity'], '')} <b>{f['severity']}</b> · <code>{f['file']}:{f['line']}</code> · {f['title']}</summary>")
            out.append("")
            out.append(finding_comment_body(f))
            out.append("")
            out.append("</details>")
        out.append("")

    filt = result.get("filter_summary") or {}
    failed = [s for s in result.get("scan_results") or [] if s.get("status") == "failed"]
    footer_bits = []
    if filt.get("total"):
        footer_bits.append(f"{filt['total']} raw finding(s) reviewed, {filt.get('kept', 0)} kept after filtering")
    if filt.get("candidates_total"):
        footer_bits.append(
            f"{filt['candidates_total']} scanner candidate(s): {filt.get('candidates_confirmed', 0)} confirmed, "
            f"{filt.get('candidates_dismissed', 0)} dismissed, {filt.get('candidates_unverified', 0)} unverified"
        )
    if failed:
        footer_bits.append("failed scans: " + ", ".join(f"{s['scan']} ({s.get('error', '')[:80]})" for s in failed))
    usage = result.get("usage") or {}
    if usage.get("input_tokens"):
        footer_bits.append(f"{usage['input_tokens']:,} input / {usage.get('output_tokens', 0):,} output tokens")
    if footer_bits:
        out.append("<sub>" + " · ".join(footer_bits) + "</sub>")
    return "\n".join(out)

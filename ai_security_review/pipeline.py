"""Orchestration: diff -> triage -> selected scans -> filter -> report."""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ai_security_review import __version__
from ai_security_review.claude_client import ClaudeCallError, ClaudeClient
from ai_security_review.constants import (
    BACKEND_API,
    DEFAULT_MIN_FINDING_CONFIDENCE,
    DEFAULT_SCAN_EFFORT,
    DEFAULT_SCAN_MODEL,
    DEFAULT_TOOLS,
    DEFAULT_TRIAGE_CONFIDENCE_THRESHOLD,
    DEFAULT_TRIAGE_EFFORT,
    DEFAULT_TRIAGE_MODEL,
    TOOL_TIMEOUT_SECONDS,
)
from ai_security_review.diff import DiffBundle, ExclusionRules
from ai_security_review.findings import normalize_finding, process_findings, resolve_candidates, severity_counts, similar_findings
from ai_security_review.logger import get_logger
from ai_security_review.prompts import describe_tool_signals
from ai_security_review.scan_runner import ScanResult, ScanRunner
from ai_security_review.tools import ToolResult, run_tools
from ai_security_review.triage import TriageResult, forced_triage, run_triage

logger = get_logger(__name__)


@dataclass
class PipelineConfig:
    repo_dir: Path
    backend: str = BACKEND_API
    triage_model: str = DEFAULT_TRIAGE_MODEL
    scan_model: str = DEFAULT_SCAN_MODEL
    triage_effort: str = DEFAULT_TRIAGE_EFFORT
    scan_effort: str = DEFAULT_SCAN_EFFORT
    triage_threshold: float = DEFAULT_TRIAGE_CONFIDENCE_THRESHOLD
    min_confidence: float = DEFAULT_MIN_FINDING_CONFIDENCE
    forced_scans: Optional[List[str]] = None       # bypass triage and run exactly these
    always_scans: List[str] = field(default_factory=list)  # run these in addition to what triage picks
    exclude_dirs: List[str] = field(default_factory=list)
    custom_triage_instructions: Optional[str] = None
    custom_scan_instructions: Dict[str, str] = field(default_factory=dict)
    include_context_files: bool = True
    require_in_diff: bool = True
    tools: List[str] = field(default_factory=lambda: list(DEFAULT_TOOLS))  # external scanners to run before triage
    tool_timeout: int = TOOL_TIMEOUT_SECONDS
    tool_options: Dict[str, str] = field(default_factory=dict)  # e.g. semgrep_config, gitleaks_config


def run_pipeline(config: PipelineConfig, bundle: DiffBundle, pr_context: Optional[Dict] = None, client: Optional[ClaudeClient] = None) -> Dict[str, Any]:
    """Run the full review and return a JSON-serialisable result dict."""
    started = time.time()
    rules = ExclusionRules(config.exclude_dirs)
    result: Dict[str, Any] = {
        "version": __version__,
        "pr": pr_context or {},
        "diff": {"files": bundle.paths, "excluded": bundle.excluded, "truncated": bundle.truncated},
        "tool_results": [],
        "triage": None,
        "scan_results": [],
        "findings": [],
        "severity_counts": severity_counts([]),
        "filter_summary": None,
        "usage": {"input_tokens": 0, "output_tokens": 0},
        "error": None,
    }

    if bundle.is_empty():
        result["triage"] = forced_triage([], reason="empty diff").to_dict()
        result["triage"]["summary"] = "No reviewable changes in the diff."
        result["duration_seconds"] = round(time.time() - started, 1)
        return result

    needs_api = config.backend == BACKEND_API or not config.forced_scans
    if needs_api and client is None:
        client = ClaudeClient()

    # 0. External scanners. Deterministic and cheap, so they run first and inform triage.
    tool_results: List[ToolResult] = run_tools(config.tools, config.repo_dir, bundle, timeout=config.tool_timeout, options=config.tool_options)
    result["tool_results"] = [t.to_dict() for t in tool_results]
    tool_findings = [f for t in tool_results for f in t.findings]
    candidates, redundant = collapse_candidates([c for t in tool_results for c in t.candidates], tool_findings)

    # 1. Triage
    try:
        if config.forced_scans is not None:
            triage = forced_triage(config.forced_scans)
        else:
            triage = run_triage(
                client,
                bundle,
                pr_context,
                model=config.triage_model,
                effort=config.triage_effort,
                threshold=config.triage_threshold,
                custom_instructions=config.custom_triage_instructions,
                tool_signals=describe_tool_signals(tool_findings, candidates) or None,
            )
    except ClaudeCallError as e:
        logger.error("Triage failed: %s", e)
        result["error"] = f"Triage failed: {e}"
        # Scanner findings are still worth reporting even when the model could not be reached.
        kept, filter_summary = process_findings(tool_findings, bundle, rules, config.min_confidence, config.require_in_diff)
        result["findings"] = kept
        result["severity_counts"] = severity_counts(kept)
        result["filter_summary"] = filter_summary.to_dict()
        result["duration_seconds"] = round(time.time() - started, 1)
        _record_usage(result, client)
        return result

    selected = list(triage.selected_scans)
    for key in config.always_scans:
        if key not in selected:
            selected.append(key)
            triage.scans[key]["reason"] = (triage.scans[key].get("reason") or "") + " (always-run)"
    if config.forced_scans is None:
        # A scanner candidate deserves a verdict from the scan that owns it, whatever triage thought.
        for key in sorted({c["owner_scan"] for c in candidates}):
            if key not in selected:
                selected.append(key)
                triage.scans[key]["reason"] = (triage.scans[key].get("reason") or "") + " (added to verify scanner candidates)"
    triage.selected_scans = selected
    result["triage"] = triage.to_dict()

    # 2. Scans
    runner = ScanRunner(
        repo_dir=config.repo_dir,
        backend=config.backend,
        client=client,
        model=config.scan_model,
        effort=config.scan_effort,
        custom_instructions=config.custom_scan_instructions,
        include_context_files=config.include_context_files,
    )
    scan_results: List[ScanResult] = runner.run_all(selected, bundle, triage.to_dict(), pr_context, candidates=candidates, tool_findings=tool_findings)
    result["scan_results"] = [s.to_dict() for s in scan_results]

    # 3. Resolve scanner candidates against the scans' verdicts, then filter + dedupe everything together
    verdicts = {v["id"]: {**v, "scan": s.scan} for s in scan_results for v in s.candidate_verdicts}
    promoted, dismissed_details, counts = resolve_candidates(candidates, verdicts, config.min_confidence)
    raw = [f for s in scan_results for f in s.findings] + tool_findings + promoted
    kept, filter_summary = process_findings(raw, bundle, rules, config.min_confidence, config.require_in_diff)
    filter_summary.candidates_total = counts["total"] + redundant
    filter_summary.candidates_confirmed = counts["confirmed"]
    filter_summary.candidates_dismissed = counts["dismissed"]
    filter_summary.candidates_unverified = counts["unverified"]
    filter_summary.merged_duplicates += redundant
    filter_summary.excluded_details.extend(dismissed_details)
    result["findings"] = kept
    result["severity_counts"] = severity_counts(kept)
    result["filter_summary"] = filter_summary.to_dict()

    failed = [s for s in scan_results if s.status == "failed"]
    if failed and len(failed) == len(scan_results):
        result["error"] = "All selected scans failed: " + "; ".join(f"{s.scan}: {s.error}" for s in failed)

    _record_usage(result, client)
    result["duration_seconds"] = round(time.time() - started, 1)
    return result


def collapse_candidates(candidates: List[Dict[str, Any]], tool_findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Drop candidates a scanner already reports outright, and fold several rules on one line into one candidate.

    Returns ``(candidates, dropped_count)``. Ids are reassigned so they stay dense and stable.
    """
    reported = [normalize_finding(f) for f in tool_findings]
    kept: List[Dict[str, Any]] = []
    dropped = 0
    for c in candidates:
        probe = normalize_finding(c)
        if any(similar_findings(probe, r) for r in reported):
            dropped += 1
            continue
        twin = next((k for k in kept if k["file"] == c["file"] and k["category"] == c["category"] and abs(k["line"] - c["line"]) <= 3), None)
        if twin is None:
            kept.append(dict(c))
            continue
        dropped += 1
        twin["rule_id"] = f"{twin['rule_id']}, {c['rule_id']}"
        twin["confidence"] = max(twin["confidence"], c["confidence"])
        if c.get("description") and c["description"] not in twin.get("description", ""):
            twin["description"] = f"{twin.get('description', '')} Also matched by '{c['rule_id']}'."
    for i, c in enumerate(kept, 1):
        c["id"] = f"{c.get('tool', 'tool')}-{i}"
    return kept, dropped


def _record_usage(result: Dict[str, Any], client: Optional[ClaudeClient]) -> None:
    if client is not None:
        result["usage"] = {"input_tokens": client.total_input_tokens, "output_tokens": client.total_output_tokens}

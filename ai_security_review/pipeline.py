"""Orchestration: diff -> triage -> selected scans -> filter -> report."""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ai_security_review import __version__
from ai_security_review.claude_client import ClaudeCallError, ClaudeClient
from ai_security_review.constants import (
    BACKEND_API,
    DEFAULT_MIN_FINDING_CONFIDENCE,
    DEFAULT_SCAN_EFFORT,
    DEFAULT_SCAN_MODEL,
    DEFAULT_TRIAGE_CONFIDENCE_THRESHOLD,
    DEFAULT_TRIAGE_EFFORT,
    DEFAULT_TRIAGE_MODEL,
    TOOL_TIMEOUT_SECONDS,
)
from ai_security_review.diff import DiffBundle, ExclusionRules
from ai_security_review.findings import collapse_candidates, normalize_finding, process_findings, resolve_candidates, severity_counts
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
    tools: List[str] = field(default_factory=list)  # external scanners to run before triage; the CLI passes DEFAULT_TOOLS
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
    unowned: List[Dict[str, Any]] = []

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
        # Scanner output is still worth reporting even when the model could not be reached.
        _finalise_findings(result, config, bundle, rules, [], tool_findings, candidates, {}, redundant)
        result["duration_seconds"] = round(time.time() - started, 1)
        _record_usage(result, client)
        return result

    for key in config.always_scans:
        triage.ensure_selected(key, "always-run")
    if config.forced_scans is None:
        # A scanner candidate deserves a verdict from the scan that owns it, whatever triage thought.
        for key in sorted({c["owner_scan"] for c in candidates}):
            triage.ensure_selected(key, "added to verify scanner candidates")
    else:
        # Forced means forced: candidates whose owner scan was not requested get no verdict and are
        # not reported on a pattern match alone.
        unowned = [c for c in candidates if c["owner_scan"] not in triage.selected_scans]
        candidates = [c for c in candidates if c["owner_scan"] in triage.selected_scans]
    selected = list(triage.selected_scans)
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
    model_findings = [f for s in scan_results for f in s.findings]
    _finalise_findings(result, config, bundle, rules, model_findings, tool_findings, candidates, verdicts, redundant, unowned)

    failed = [s for s in scan_results if s.status == "failed"]
    if failed and len(failed) == len(scan_results):
        result["error"] = "All selected scans failed: " + "; ".join(f"{s.scan}: {s.error}" for s in failed)

    _record_usage(result, client)
    result["duration_seconds"] = round(time.time() - started, 1)
    return result


def _finalise_findings(
    result: Dict[str, Any],
    config: PipelineConfig,
    bundle: DiffBundle,
    rules: ExclusionRules,
    model_findings: List[Dict[str, Any]],
    tool_findings: List[Dict[str, Any]],
    candidates: List[Dict[str, Any]],
    verdicts: Dict[str, Dict[str, Any]],
    redundant: int,
    unowned: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Resolve candidates, then run every finding through the single filter + dedupe pass."""
    promoted, dismissed_details, counts = resolve_candidates(candidates, verdicts)
    kept, summary = process_findings(
        model_findings + tool_findings + promoted, bundle, rules, config.min_confidence, config.require_in_diff
    )
    summary.candidates_total = counts["total"] + redundant + len(unowned or [])
    summary.candidates_confirmed = counts["confirmed"]
    summary.candidates_dismissed = counts["dismissed"]
    summary.candidates_unverified = counts["unverified"] + len(unowned or [])
    summary.merged_duplicates += redundant
    summary.excluded_details.extend(dismissed_details)
    for c in unowned or []:
        summary.excluded_details.append(
            {**normalize_finding(c), "excluded_reason": f"Scanner candidate for the {c['owner_scan']} scan, which was not among the forced scans"}
        )
    result["findings"] = kept
    result["severity_counts"] = severity_counts(kept)
    result["filter_summary"] = summary.to_dict()


def _record_usage(result: Dict[str, Any], client: Optional[ClaudeClient]) -> None:
    if client is not None:
        result["usage"] = {"input_tokens": client.total_input_tokens, "output_tokens": client.total_output_tokens}

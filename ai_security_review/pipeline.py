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
)
from ai_security_review.diff import DiffBundle, ExclusionRules
from ai_security_review.findings import process_findings, severity_counts
from ai_security_review.logger import get_logger
from ai_security_review.scan_runner import ScanResult, ScanRunner
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


def run_pipeline(config: PipelineConfig, bundle: DiffBundle, pr_context: Optional[Dict] = None, client: Optional[ClaudeClient] = None) -> Dict[str, Any]:
    """Run the full review and return a JSON-serialisable result dict."""
    started = time.time()
    rules = ExclusionRules(config.exclude_dirs)
    result: Dict[str, Any] = {
        "version": __version__,
        "pr": pr_context or {},
        "diff": {"files": bundle.paths, "excluded": bundle.excluded, "truncated": bundle.truncated},
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
            )
    except ClaudeCallError as e:
        logger.error("Triage failed: %s", e)
        result["error"] = f"Triage failed: {e}"
        result["duration_seconds"] = round(time.time() - started, 1)
        _record_usage(result, client)
        return result

    selected = list(triage.selected_scans)
    for key in config.always_scans:
        if key not in selected:
            selected.append(key)
            triage.scans[key]["reason"] = (triage.scans[key].get("reason") or "") + " (always-run)"
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
    scan_results: List[ScanResult] = runner.run_all(selected, bundle, triage.to_dict(), pr_context)
    result["scan_results"] = [s.to_dict() for s in scan_results]

    # 3. Filter + dedupe
    raw = [f for s in scan_results for f in s.findings]
    kept, filter_summary = process_findings(raw, bundle, rules, config.min_confidence, config.require_in_diff)
    result["findings"] = kept
    result["severity_counts"] = severity_counts(kept)
    result["filter_summary"] = filter_summary.to_dict()

    failed = [s for s in scan_results if s.status == "failed"]
    if failed and len(failed) == len(scan_results):
        result["error"] = "All selected scans failed: " + "; ".join(f"{s.scan}: {s.error}" for s in failed)

    _record_usage(result, client)
    result["duration_seconds"] = round(time.time() - started, 1)
    return result


def _record_usage(result: Dict[str, Any], client: Optional[ClaudeClient]) -> None:
    if client is not None:
        result["usage"] = {"input_tokens": client.total_input_tokens, "output_tokens": client.total_output_tokens}

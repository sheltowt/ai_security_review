"""Open-source scanners that run alongside the model scans.

- ``gitleaks``: secret detection. Deterministic, near-free, runs on every diff; its hits are reported
  directly because a model cannot verify a credential anyway.
- ``semgrep``:  static analysis. Its hits become candidates that the owning model scan confirms or
  dismisses, so the review keeps the precision bar the model scans set.

Both run in parallel before triage. Their output is shown to triage as routing signals and to the scans
as candidates or as already-reported findings.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from ai_security_review.constants import ALL_TOOLS, TOOL_GITLEAKS, TOOL_SEMGREP, TOOL_TIMEOUT_SECONDS
from ai_security_review.diff import DiffBundle
from ai_security_review.logger import get_logger
from ai_security_review.tools.base import Tool, ToolError, ToolResult
from ai_security_review.tools.gitleaks import GitleaksTool
from ai_security_review.tools.semgrep import SemgrepTool

logger = get_logger(__name__)

_REGISTRY = {
    TOOL_GITLEAKS: GitleaksTool,
    TOOL_SEMGREP: SemgrepTool,
}


def get_tool(key: str, timeout: int = TOOL_TIMEOUT_SECONDS, options: Optional[Dict[str, str]] = None) -> Tool:
    try:
        cls = _REGISTRY[key]
    except KeyError as e:
        raise ValueError(f"Unknown tool '{key}'. Valid tools: {', '.join(ALL_TOOLS)}") from e
    options = options or {}
    if key == TOOL_SEMGREP:
        return cls(timeout=timeout, config=options.get("semgrep_config"))
    if key == TOOL_GITLEAKS:
        return cls(timeout=timeout, config_path=options.get("gitleaks_config"))
    return cls(timeout=timeout)


def run_tools(
    keys: Sequence[str],
    repo_dir: Path,
    bundle: DiffBundle,
    timeout: int = TOOL_TIMEOUT_SECONDS,
    options: Optional[Dict[str, str]] = None,
) -> List[ToolResult]:
    """Run the named tools concurrently and return their results in the order given."""
    keys = [k for k in keys if k]
    if not keys or bundle.is_empty():
        return []
    tools = [get_tool(k, timeout, options) for k in keys]
    results: Dict[str, ToolResult] = {}
    with ThreadPoolExecutor(max_workers=len(tools)) as pool:
        futures = {pool.submit(t.run, repo_dir, bundle): t.key for t in tools}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as e:  # Tool.run already guards; belt and braces
                logger.exception("tool %s crashed", key)
                results[key] = ToolResult(tool=key, status="failed", error=str(e))
    return [results[t.key] for t in tools]


__all__ = ["Tool", "ToolError", "ToolResult", "GitleaksTool", "SemgrepTool", "get_tool", "run_tools"]

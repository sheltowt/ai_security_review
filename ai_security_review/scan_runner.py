"""Run a scan through either the Messages API or a headless Claude Code process."""

import json
import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ai_security_review.claude_client import ClaudeCallError, ClaudeClient
from ai_security_review.constants import (
    BACKEND_API,
    BACKEND_CLAUDE_CODE,
    CLAUDE_CODE_ALLOWED_TOOLS,
    CLAUDE_CODE_TIMEOUT_SECONDS,
    DEFAULT_SCAN_EFFORT,
    DEFAULT_SCAN_MODEL,
    SCAN_MAX_TOKENS,
)
from ai_security_review.diff import DiffBundle, collect_context_files
from ai_security_review.json_parser import parse_json_with_fallbacks
from ai_security_review.logger import get_logger
from ai_security_review.prompts import (
    build_scan_system_prompt,
    build_scan_user_prompt,
    scan_output_instructions_for_cli,
)
from ai_security_review.scans import SCAN_RESULT_SCHEMA, ScanDefinition, get_scan

logger = get_logger(__name__)


@dataclass
class ScanResult:
    scan: str
    status: str                           # completed | failed | skipped
    findings: List[Dict[str, Any]] = field(default_factory=list)
    candidate_verdicts: List[Dict[str, Any]] = field(default_factory=list)
    reviewed_files: List[str] = field(default_factory=list)
    notes: str = ""
    error: Optional[str] = None
    model: Optional[str] = None
    backend: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan": self.scan,
            "status": self.status,
            "findings_count": len(self.findings),
            "candidate_verdicts": self.candidate_verdicts,
            "reviewed_files": self.reviewed_files,
            "notes": self.notes,
            "error": self.error,
            "model": self.model,
            "backend": self.backend,
            "duration_seconds": round(self.duration_seconds, 1),
        }


def _clean_verdicts(verdicts: Any) -> List[Dict[str, Any]]:
    out = []
    for v in verdicts or []:
        if not isinstance(v, dict) or not v.get("id"):
            continue
        verdict = str(v.get("verdict") or "unsure").lower()
        if verdict not in ("confirmed", "dismissed", "unsure"):
            verdict = "unsure"
        out.append({"id": str(v["id"]), "verdict": verdict, "reason": str(v.get("reason") or "")})
    return out


def _tag_findings(findings: Any, scan_key: str) -> List[Dict[str, Any]]:
    tagged = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        f = dict(f)
        f["scan"] = scan_key
        tagged.append(f)
    return tagged


class ScanRunner:
    def __init__(
        self,
        repo_dir: Path,
        backend: str = BACKEND_API,
        client: Optional[ClaudeClient] = None,
        model: str = DEFAULT_SCAN_MODEL,
        effort: str = DEFAULT_SCAN_EFFORT,
        custom_instructions: Optional[Dict[str, str]] = None,
        claude_code_timeout: int = CLAUDE_CODE_TIMEOUT_SECONDS,
        include_context_files: bool = True,
        max_workers: int = 3,
    ):
        self.repo_dir = repo_dir
        self.backend = backend
        self.client = client
        self.model = model
        self.effort = effort
        self.custom_instructions = custom_instructions or {}
        self.claude_code_timeout = claude_code_timeout
        self.include_context_files = include_context_files
        self.max_workers = max_workers

    # ---- public -------------------------------------------------------------------

    def run_all(
        self,
        scan_keys: List[str],
        bundle: DiffBundle,
        triage: Dict,
        pr_context: Optional[Dict] = None,
        candidates: Optional[List[Dict[str, Any]]] = None,
        tool_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[ScanResult]:
        if not scan_keys:
            return []
        context_files = collect_context_files(self.repo_dir, bundle) if (self.include_context_files and self.backend == BACKEND_API) else {}
        results: Dict[str, ScanResult] = {}
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(scan_keys))) as pool:
            futures = {
                pool.submit(self.run_one, key, bundle, triage, pr_context, context_files, candidates, tool_findings): key
                for key in scan_keys
            }
            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as e:  # defensive: run_one already catches, but never lose a scan
                    logger.exception("scan %s crashed", key)
                    results[key] = ScanResult(scan=key, status="failed", error=str(e), backend=self.backend)
        return [results[k] for k in scan_keys]

    def run_one(
        self,
        scan_key: str,
        bundle: DiffBundle,
        triage: Dict,
        pr_context: Optional[Dict] = None,
        context_files: Optional[Dict[str, str]] = None,
        candidates: Optional[List[Dict[str, Any]]] = None,
        tool_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> ScanResult:
        started = time.time()
        try:
            scan = get_scan(scan_key)
            mine = [c for c in (candidates or []) if c.get("owner_scan") == scan.key]
            reported = [f for f in (tool_findings or []) if f.get("category") in scan.categories]
            if self.backend == BACKEND_CLAUDE_CODE:
                result = self._run_claude_code(scan, bundle, triage, pr_context, mine, reported)
            else:
                result = self._run_api(scan, bundle, triage, pr_context, context_files or {}, mine, reported)
        except ClaudeCallError as e:
            result = ScanResult(scan=scan_key, status="failed", error=str(e))
        except Exception as e:
            logger.exception("scan %s failed", scan_key)
            result = ScanResult(scan=scan_key, status="failed", error=f"{type(e).__name__}: {e}")
        result.backend = self.backend
        result.duration_seconds = time.time() - started
        logger.info("scan %s: %s (%d findings, %.0fs)", scan_key, result.status, len(result.findings), result.duration_seconds)
        return result

    # ---- backends -----------------------------------------------------------------

    def _run_api(
        self,
        scan: ScanDefinition,
        bundle: DiffBundle,
        triage: Dict,
        pr_context: Optional[Dict],
        context_files: Dict[str, str],
        candidates: Optional[List[Dict[str, Any]]] = None,
        reported: Optional[List[Dict[str, Any]]] = None,
    ) -> ScanResult:
        if self.client is None:
            raise ClaudeCallError("API backend requires a ClaudeClient")
        response = self.client.structured_call(
            model=self.model,
            system=build_scan_system_prompt(scan, self.custom_instructions.get(scan.key)),
            user=build_scan_user_prompt(
                scan, bundle, triage, pr_context, context_files=context_files, candidates=candidates, reported_by_tools=reported
            ),
            schema=SCAN_RESULT_SCHEMA,
            max_tokens=SCAN_MAX_TOKENS,
            effort=self.effort,
            label=f"scan:{scan.key}",
        )
        data = response.data if isinstance(response.data, dict) else {}
        return ScanResult(
            scan=scan.key,
            status="completed",
            findings=_tag_findings(data.get("findings"), scan.key),
            candidate_verdicts=_clean_verdicts(data.get("candidate_verdicts")),
            reviewed_files=[str(p) for p in (data.get("reviewed_files") or [])],
            notes=str(data.get("notes", "")),
            model=response.model,
        )

    def _run_claude_code(
        self,
        scan: ScanDefinition,
        bundle: DiffBundle,
        triage: Dict,
        pr_context: Optional[Dict],
        candidates: Optional[List[Dict[str, Any]]] = None,
        reported: Optional[List[Dict[str, Any]]] = None,
    ) -> ScanResult:
        if shutil.which("claude") is None:
            raise ClaudeCallError("Claude Code CLI ('claude') not found on PATH")
        system = build_scan_system_prompt(scan, self.custom_instructions.get(scan.key))
        user = build_scan_user_prompt(
            scan, bundle, triage, pr_context, repo_exploration_available=True, candidates=candidates, reported_by_tools=reported
        )
        prompt = user + scan_output_instructions_for_cli(json.dumps(SCAN_RESULT_SCHEMA, indent=2))

        cmd = [
            "claude",
            "-p",
            "--output-format", "json",
            "--model", self.model,
            "--append-system-prompt", system,
            "--allowedTools", CLAUDE_CODE_ALLOWED_TOOLS,
            "--disallowedTools", "Write,Edit,MultiEdit,NotebookEdit,WebFetch,WebSearch,Bash(rm:*),Bash(curl:*),Bash(wget:*)",
        ]
        env = dict(os.environ)
        env.setdefault("CLAUDE_CODE_MAX_OUTPUT_TOKENS", str(SCAN_MAX_TOKENS))

        last_error = "unknown error"
        for attempt in range(1, 3):
            try:
                proc = subprocess.run(
                    cmd,
                    input=prompt,
                    cwd=self.repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=self.claude_code_timeout,
                    env=env,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                raise ClaudeCallError(f"scan:{scan.key}: Claude Code timed out after {self.claude_code_timeout}s")
            if proc.returncode != 0:
                last_error = f"Claude Code exited {proc.returncode}: {proc.stderr.strip()[:1000]}"
                logger.warning("scan %s attempt %d: %s", scan.key, attempt, last_error)
                time.sleep(5 * attempt)
                continue
            ok, wrapper = parse_json_with_fallbacks(proc.stdout, f"scan:{scan.key} claude output")
            if not ok:
                last_error = wrapper.get("error", "unparseable output")
                continue
            if isinstance(wrapper, dict) and wrapper.get("is_error"):
                last_error = f"Claude Code reported an error: {str(wrapper.get('result'))[:500]}"
                if "too long" in str(wrapper.get("result", "")).lower():
                    raise ClaudeCallError(f"scan:{scan.key}: {last_error}")
                continue
            result_text = wrapper.get("result") if isinstance(wrapper, dict) else None
            ok, data = parse_json_with_fallbacks(result_text or "", f"scan:{scan.key} result")
            if not ok or not isinstance(data, dict) or "findings" not in data:
                last_error = "Claude Code result did not contain a findings object"
                continue
            return ScanResult(
                scan=scan.key,
                status="completed",
                findings=_tag_findings(data.get("findings"), scan.key),
                candidate_verdicts=_clean_verdicts(data.get("candidate_verdicts")),
                reviewed_files=[str(p) for p in (data.get("reviewed_files") or [])],
                notes=str(data.get("notes", "")),
                model=self.model,
            )
        raise ClaudeCallError(f"scan:{scan.key}: {last_error}")

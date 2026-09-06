"""Shared plumbing for external open-source scanners.

A tool runs before triage, on the touched files only, and returns two kinds of output:

- ``findings``:   ready to report. They enter the same normalise / filter / dedupe stage as model
                  findings, tagged with the tool name as their ``scan``.
- ``candidates``: hits that need a model's judgement before they are worth a PR comment (typical of
                  SAST rules with low precision). Each candidate names the scan that owns its category;
                  that scan is asked to confirm or dismiss it.

Missing binaries make a tool ``skipped``; crashes make it ``failed``. Neither stops the review.
"""

import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ai_security_review.constants import TOOL_TIMEOUT_SECONDS
from ai_security_review.diff import DiffBundle, DiffFile
from ai_security_review.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ToolResult:
    tool: str
    status: str                                   # completed | skipped | failed
    version: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    notes: str = ""
    error: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status,
            "version": self.version,
            "findings_count": len(self.findings),
            "candidates_count": len(self.candidates),
            "notes": self.notes,
            "error": self.error,
            "duration_seconds": round(self.duration_seconds, 1),
        }


class ToolError(Exception):
    """Raised by a tool when the external process fails in a way worth surfacing."""


class Tool:
    """Base class. Subclasses set ``key`` and ``binaries`` and implement :meth:`scan`."""

    key: str = ""
    binaries: Tuple[str, ...] = ()
    version_args: Tuple[str, ...] = ("--version",)

    def __init__(self, timeout: int = TOOL_TIMEOUT_SECONDS):
        self.timeout = timeout

    # ---- discovery ----------------------------------------------------------------

    def executable(self) -> Optional[str]:
        for name in self.binaries:
            path = shutil.which(name)
            if path:
                return path
        return None

    def version(self, exe: str) -> Optional[str]:
        try:
            proc = self._exec([exe, *self.version_args], timeout=30)
        except Exception:  # version is informational only
            return None
        text = (proc.stdout or proc.stderr or "").strip().splitlines()
        return text[0][:60] if text else None

    # ---- execution ----------------------------------------------------------------

    def run(self, repo_dir: Path, bundle: DiffBundle) -> ToolResult:
        started = time.time()
        exe = self.executable()
        if exe is None:
            result = ToolResult(tool=self.key, status="skipped", notes=f"'{self.binaries[0]}' not found on PATH")
        else:
            try:
                result = self.scan(exe, repo_dir, bundle)
                result.version = self.version(exe)
            except subprocess.TimeoutExpired:
                result = ToolResult(tool=self.key, status="failed", error=f"timed out after {self.timeout}s")
            except ToolError as e:
                result = ToolResult(tool=self.key, status="failed", error=str(e))
            except Exception as e:  # never let a scanner crash the review
                logger.exception("tool %s crashed", self.key)
                result = ToolResult(tool=self.key, status="failed", error=f"{type(e).__name__}: {e}")
        result.duration_seconds = time.time() - started
        logger.info(
            "tool %s: %s (%d findings, %d candidates, %.1fs)%s",
            self.key, result.status, len(result.findings), len(result.candidates), result.duration_seconds,
            f" - {result.error or result.notes}" if result.status != "completed" else "",
        )
        return result

    def scan(self, exe: str, repo_dir: Path, bundle: DiffBundle) -> ToolResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def _exec(self, cmd: Sequence[str], cwd: Optional[Path] = None, timeout: Optional[int] = None, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            list(cmd),
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout or self.timeout,
            env=env,
            check=False,
        )

    # ---- helpers for subclasses ---------------------------------------------------

    @staticmethod
    def present_files(repo_dir: Path, bundle: DiffBundle) -> List[DiffFile]:
        """Touched, non-deleted files that exist in the checkout (the post-change side)."""
        out = []
        for f in bundle.files:
            if f.status == "deleted":
                continue
            if (repo_dir / f.path).is_file():
                out.append(f)
        return out

    @staticmethod
    def overlaps_added_lines(f: DiffFile, start: int, end: Optional[int] = None) -> bool:
        end = end or start
        return any(start <= n <= end for n in f.added_lines)

    @staticmethod
    def make_finding(
        *,
        tool: str,
        rule_id: str,
        file: str,
        line: int,
        severity: str,
        category: str,
        title: str,
        description: str,
        recommendation: str,
        confidence: float,
        exploit_scenario: str = "",
        introduced_by_change: bool = True,
    ) -> Dict[str, Any]:
        return {
            "file": file,
            "line": line,
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "exploit_scenario": exploit_scenario,
            "recommendation": recommendation,
            "confidence": confidence,
            "introduced_by_change": introduced_by_change,
            "scan": tool,
            "tool": tool,
            "rule_id": rule_id,
        }


def read_snippet(repo_dir: Path, path: str, start: int, end: int, max_chars: int = 300) -> str:
    """Return the source lines ``start..end`` of a file, bounded, or '' if unavailable."""
    try:
        lines = (repo_dir / path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    chunk = "\n".join(lines[max(0, start - 1): max(start, end)])
    return chunk[:max_chars]

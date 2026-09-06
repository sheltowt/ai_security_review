"""Secret detection with gitleaks (https://github.com/gitleaks/gitleaks, MIT).

The touched files are copied into a temporary tree and scanned with ``gitleaks dir``. Only hits on
lines the diff added are reported. A second tree holds just the lines the diff *removed*: a secret found
there has already leaked into git history, and the finding says so and asks for rotation.

Secret values never leave the scanner: gitleaks runs with ``--redact`` and the finding text carries only
the rule id, the description, and the line.
"""

import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ai_security_review.constants import (
    GITLEAKS_CONFIG,
    SECRET_FINDING_CONFIDENCE,
    SECRET_IN_HISTORY_CONFIDENCE,
    TOOL_GITLEAKS,
    TOOL_TIMEOUT_SECONDS,
)
from ai_security_review.diff import DiffBundle, DiffFile
from ai_security_review.tools.base import Tool, ToolError, ToolResult

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_ADDED_ROOT = "added"
_REMOVED_ROOT = "removed"


def removed_lines_with_positions(f: DiffFile) -> Tuple[List[str], List[int]]:
    """The '-' lines of a file's patch and, for each, the new-side line where the removal happened."""
    lines: List[str] = []
    positions: List[int] = []
    new_line = 0
    in_hunk = False
    for line in f.patch.splitlines():
        hunk = _HUNK_HEADER.match(line)
        if hunk:
            new_line = int(hunk.group(3))
            in_hunk = True
            continue
        if not in_hunk or line.startswith(("+++", "---", "\\")):
            continue
        if line.startswith("-"):
            lines.append(line[1:])
            positions.append(max(1, new_line))
        elif line.startswith("+"):
            new_line += 1
        else:
            new_line += 1
    return lines, positions


class GitleaksTool(Tool):
    key = TOOL_GITLEAKS
    binaries = ("gitleaks",)
    version_args = ("version",)

    def __init__(self, timeout: Optional[int] = None, config_path: Optional[str] = None):
        super().__init__(timeout or TOOL_TIMEOUT_SECONDS)
        self.config_path = config_path if config_path is not None else GITLEAKS_CONFIG

    def scan(self, exe: str, repo_dir: Path, bundle: DiffBundle) -> ToolResult:
        present = self.present_files(repo_dir, bundle)
        with tempfile.TemporaryDirectory(prefix="ai-security-review-gitleaks-") as tmp:
            root = Path(tmp)
            copied = self._stage_files(root, repo_dir, present, bundle)
            if not copied:
                return ToolResult(tool=self.key, status="completed", notes="no touched files to scan")
            raw = self._run_gitleaks(exe, root, repo_dir)

        by_path = {f.path: f for f in bundle.files}
        removed_positions = {f.path: removed_lines_with_positions(f)[1] for f in bundle.files}
        findings: List[Dict[str, Any]] = []
        added_hits = set()
        history_hits: List[Dict[str, Any]] = []

        for hit in raw:
            rel = str(hit.get("File") or "").replace("\\", "/").removeprefix("./")
            tree, _, path = rel.partition("/")
            f = by_path.get(path)
            if f is None:
                continue
            rule = str(hit.get("RuleID") or "secret")
            start = int(hit.get("StartLine") or 1)
            end = int(hit.get("EndLine") or start)
            if tree == _ADDED_ROOT:
                if not self.overlaps_added_lines(f, start, end):
                    continue  # pre-existing secret in an unchanged line; not this change's problem
                added_hits.add((path, rule))
                findings.append(self._added_finding(hit, path, rule, start))
            elif tree == _REMOVED_ROOT:
                positions = removed_positions.get(path) or []
                line = positions[start - 1] if 0 < start <= len(positions) else (f.added_lines[0] if f.added_lines else 1)
                history_hits.append(self._history_finding(hit, path, rule, line))

        # A secret that was moved rather than deleted is already reported by the added-side hit.
        for h in history_hits:
            if (h["file"], h["rule_id"]) not in added_hits:
                findings.append(h)

        notes = f"scanned {len(copied)} touched file(s); {len(findings)} secret finding(s)"
        return ToolResult(tool=self.key, status="completed", findings=findings, notes=notes)

    # ---- staging --------------------------------------------------------------------

    def _stage_files(self, root: Path, repo_dir: Path, present: List[DiffFile], bundle: DiffBundle) -> List[str]:
        copied: List[str] = []
        for f in present:
            target = root / _ADDED_ROOT / f.path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(repo_dir / f.path, target)
            copied.append(f.path)
        for f in bundle.files:
            lines, _ = removed_lines_with_positions(f)
            if not lines:
                continue
            target = root / _REMOVED_ROOT / f.path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")
            if f.path not in copied:
                copied.append(f.path)
        # Honour the repository's own gitleaks configuration. Fingerprints in .gitleaksignore are
        # path-based, so each is duplicated with both staging prefixes so it still matches here.
        toml = repo_dir / ".gitleaks.toml"
        if toml.is_file():
            shutil.copyfile(toml, root / ".gitleaks.toml")
        ignore = repo_dir / ".gitleaksignore"
        if ignore.is_file():
            lines = []
            for raw in ignore.read_text(encoding="utf-8", errors="replace").splitlines():
                entry = raw.strip()
                lines.append(raw)
                if entry and not entry.startswith("#"):
                    lines.append(f"{_ADDED_ROOT}/{entry}")
                    lines.append(f"{_REMOVED_ROOT}/{entry}")
            (root / ".gitleaksignore").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return copied

    # ---- execution ------------------------------------------------------------------

    def _run_gitleaks(self, exe: str, root: Path, repo_dir: Path) -> List[Dict[str, Any]]:
        report = root / "report.json"
        cmd = [
            exe, "dir", ".",
            "--no-banner", "--no-color", "--redact",
            "--exit-code", "0",
            "--report-format", "json",
            "--report-path", str(report),
            "--log-level", "error",
        ]
        if self.config_path:
            cmd += ["--config", str(Path(self.config_path).expanduser())]
        elif (root / ".gitleaks.toml").is_file():
            cmd += ["--config", str(root / ".gitleaks.toml")]
        proc = self._exec(cmd, cwd=root)
        if proc.returncode != 0:
            raise ToolError(f"gitleaks exited {proc.returncode}: {(proc.stderr or proc.stdout).strip()[:500]}")
        try:
            data = json.loads(report.read_text(encoding="utf-8") or "[]")
        except (OSError, json.JSONDecodeError) as e:
            raise ToolError(f"could not read gitleaks report: {e}") from e
        return [h for h in data if isinstance(h, dict)] if isinstance(data, list) else []

    # ---- finding builders -----------------------------------------------------------

    @staticmethod
    def _describe(hit: Dict[str, Any], rule: str) -> str:
        text = str(hit.get("Description") or "").strip()
        return text or f"Matches the gitleaks rule '{rule}'."

    def _added_finding(self, hit: Dict[str, Any], path: str, rule: str, line: int) -> Dict[str, Any]:
        return self.make_finding(
            tool=self.key,
            rule_id=rule,
            file=path,
            line=line,
            severity="HIGH",
            category="hardcoded_secret",
            title=f"Hardcoded secret ({rule})",
            description=f"gitleaks matched rule '{rule}' on a line added by this change. {self._describe(hit, rule)} The value has been redacted from this report.",
            exploit_scenario="Anyone with read access to the repository, its history, build logs, or a leaked archive can use the credential.",
            recommendation="Remove the secret from the code, load it from a secret store or environment at runtime, and rotate the credential since it is now in git history.",
            confidence=SECRET_FINDING_CONFIDENCE,
        )

    def _history_finding(self, hit: Dict[str, Any], path: str, rule: str, line: int) -> Dict[str, Any]:
        return self.make_finding(
            tool=self.key,
            rule_id=rule,
            file=path,
            line=line,
            severity="MEDIUM",
            category="secret_in_history",
            title=f"Removed secret remains in git history ({rule})",
            description=f"This change removes a line that gitleaks identifies as a secret (rule '{rule}'). {self._describe(hit, rule)} Deleting it from the file does not remove it from git history.",
            exploit_scenario="Anyone who can read the repository history can recover the credential from the earlier commit.",
            recommendation="Rotate the credential. If the history must be scrubbed as well, rewrite it with git filter-repo and force-push, then invalidate forks and caches.",
            confidence=SECRET_IN_HISTORY_CONFIDENCE,
        )

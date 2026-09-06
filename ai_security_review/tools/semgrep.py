"""Static analysis with Semgrep (https://semgrep.dev, LGPL engine) or its fork Opengrep.

Semgrep runs on the touched files with a security ruleset and every hit that overlaps an added line
becomes a *candidate*: the review does not trust a pattern match on its own. Each candidate is mapped
to a finding category through its CWE, handed to the scan that owns that category, and reported only
when the model confirms it, or when the rule's own confidence is high and no scan looked at it.

Rule metadata drives the initial confidence: Semgrep marks most registry rules LOW confidence and
``audit`` subcategory, which is exactly the kind of hit that benefits from a model tracing the flow.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ai_security_review.constants import SEMGREP_CONFIG, TOOL_SEMGREP, TOOL_TIMEOUT_SECONDS
from ai_security_review.diff import DiffBundle
from ai_security_review.tools.base import Tool, ToolError, ToolResult, read_snippet
from ai_security_review.tools.categories import category_for_cwes, is_suppressed, owner_scan

_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
_CONFIDENCE = {"HIGH": 0.8, "MEDIUM": 0.65, "LOW": 0.5}
_DEFAULT_CONFIDENCE = 0.55
# Categories whose matched source must not be echoed into prompts or comments.
_NO_SNIPPET = {"hardcoded_secret", "secret_in_history"}
_MAX_CANDIDATES = 40
_ACRONYMS = {"sql", "nosql", "xss", "xxe", "csrf", "ssrf", "jwt", "ldap", "xpath", "iv", "cors", "iam", "rbac", "pii", "mfa", "sso", "oauth", "dom", "url", "html", "http"}


def category_title(category: str) -> str:
    """'sql_injection' -> 'SQL injection'; 'xss_dom' -> 'XSS DOM'."""
    words = [w.upper() if w in _ACRONYMS else w for w in category.split("_")]
    if words and words[0] == words[0].lower():
        words[0] = words[0].capitalize()
    return " ".join(words)


class SemgrepTool(Tool):
    key = TOOL_SEMGREP
    binaries = ("semgrep", "opengrep")

    def __init__(self, timeout: Optional[int] = None, config: Optional[str] = None):
        super().__init__(timeout or TOOL_TIMEOUT_SECONDS)
        self.config = config or SEMGREP_CONFIG

    def scan(self, exe: str, repo_dir: Path, bundle: DiffBundle) -> ToolResult:
        present = self.present_files(repo_dir, bundle)
        if not present:
            return ToolResult(tool=self.key, status="completed", notes="no touched files to scan")
        paths = [f.path for f in present]
        data = self._run_semgrep(exe, repo_dir, paths)

        by_path = {f.path: f for f in present}
        candidates: List[Dict[str, Any]] = []
        skipped_not_security = skipped_unchanged = skipped_suppressed = 0
        for r in data.get("results") or []:
            extra = r.get("extra") or {}
            meta = extra.get("metadata") or {}
            path = str(r.get("path") or "").replace("\\", "/").removeprefix("./")
            f = by_path.get(path)
            if f is None:
                continue
            if extra.get("is_ignored"):
                continue
            cwes = meta.get("cwe")
            if str(meta.get("category") or "security").lower() != "security" and not cwes:
                skipped_not_security += 1
                continue
            if is_suppressed(cwes):
                skipped_suppressed += 1
                continue
            start = int((r.get("start") or {}).get("line") or 1)
            end = int((r.get("end") or {}).get("line") or start)
            if not self.overlaps_added_lines(f, start, end):
                skipped_unchanged += 1
                continue
            candidates.append(self._candidate(repo_dir, r, extra, meta, path, start, end))

        candidates.sort(key=lambda c: (-c["confidence"], c["file"], c["line"]))
        truncated = len(candidates) > _MAX_CANDIDATES
        candidates = candidates[:_MAX_CANDIDATES]
        for i, c in enumerate(candidates, 1):
            c["id"] = f"semgrep-{i}"

        errors = [str(e.get("message") or e) for e in (data.get("errors") or []) if isinstance(e, dict)]
        notes_bits = [f"scanned {len(paths)} touched file(s) with '{self.config}'", f"{len(candidates)} candidate(s)"]
        if skipped_unchanged:
            notes_bits.append(f"{skipped_unchanged} hit(s) on unchanged lines ignored")
        if skipped_not_security or skipped_suppressed:
            notes_bits.append(f"{skipped_not_security + skipped_suppressed} non-security or out-of-scope hit(s) ignored")
        if truncated:
            notes_bits.append(f"truncated to the top {_MAX_CANDIDATES}")
        if errors:
            notes_bits.append(f"{len(errors)} semgrep error(s): {errors[0][:120]}")
        return ToolResult(tool=self.key, status="completed", candidates=candidates, notes="; ".join(notes_bits))

    # ---- execution ------------------------------------------------------------------

    def _run_semgrep(self, exe: str, repo_dir: Path, paths: List[str]) -> Dict[str, Any]:
        cmd = [
            exe, "scan",
            "--json", "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--config", self.config,
            "--timeout", "60",
            *paths,
        ]
        proc = self._exec(cmd, cwd=repo_dir)
        stdout = (proc.stdout or "").strip()
        if not stdout:
            raise ToolError(f"semgrep exited {proc.returncode} with no output: {(proc.stderr or '').strip()[:500]}")
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise ToolError(f"semgrep produced unparseable JSON (exit {proc.returncode}): {e}") from e
        if not isinstance(data, dict):
            raise ToolError("semgrep output was not a JSON object")
        if proc.returncode not in (0, 1) and not data.get("results"):
            first = (data.get("errors") or [{}])[0]
            message = first.get("message") if isinstance(first, dict) else str(first)
            raise ToolError(f"semgrep exited {proc.returncode}: {str(message or proc.stderr).strip()[:500]}")
        return data

    # ---- candidate builder ----------------------------------------------------------

    def _candidate(self, repo_dir: Path, r: Dict, extra: Dict, meta: Dict, path: str, start: int, end: int) -> Dict[str, Any]:
        rule_id = str(r.get("check_id") or "semgrep-rule")
        category = category_for_cwes(meta.get("cwe")) or "security_issue"
        subcategory = [str(s).lower() for s in (meta.get("subcategory") or [])]
        confidence = _CONFIDENCE.get(str(meta.get("confidence") or "").upper(), _DEFAULT_CONFIDENCE)
        if "vuln" in subcategory:
            confidence += 0.05
        elif "audit" in subcategory:
            confidence -= 0.05
        confidence = round(max(0.1, min(0.95, confidence)), 2)
        message = " ".join(str(extra.get("message") or "").split())
        short_rule = rule_id.rsplit(".", 1)[-1]
        refs = [str(u) for u in (meta.get("references") or [])][:2]

        finding = self.make_finding(
            tool=self.key,
            rule_id=rule_id,
            file=path,
            line=start,
            severity=_SEVERITY.get(str(extra.get("severity") or "").upper(), "MEDIUM"),
            category=category,
            title=f"{category_title(category)} ({short_rule})",
            description=f"Semgrep rule '{rule_id}' matched lines {start}-{end}. {message}",
            recommendation=(extra.get("fix") and f"Suggested fix: {extra['fix']}") or (refs and "See: " + ", ".join(refs)) or "Review the flagged code and apply the fix recommended by the rule documentation.",
            confidence=confidence,
        )
        finding.update({
            "id": "",
            "owner_scan": owner_scan(category),
            "end_line": end,
            "cwe": [str(c) for c in (meta.get("cwe") if isinstance(meta.get("cwe"), list) else [meta.get("cwe")]) if c],
            "snippet": "" if category in _NO_SNIPPET else read_snippet(repo_dir, path, start, end),
        })
        return finding

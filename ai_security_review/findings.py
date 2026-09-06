"""Normalise, filter, and de-duplicate findings from the scans."""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern, Tuple

from ai_security_review.constants import DEFAULT_MIN_FINDING_CONFIDENCE, SEVERITIES
from ai_security_review.diff import DiffBundle, ExclusionRules
from ai_security_review.logger import get_logger

logger = get_logger(__name__)


class HardExclusionRules:
    """Cheap regex rules for finding classes we never want in a PR comment."""

    _PATTERNS: List[Tuple[str, Pattern]] = [
        ("Denial of service / resource exhaustion (out of scope)", re.compile(r"\b(denial[- ]of[- ]service|\bdos\b|resource exhaustion|exhaust(?:s|ing)? (?:memory|cpu|resources)|unbounded (?:loop|recursion|growth))\b", re.I)),
        ("Rate limiting recommendation (out of scope)", re.compile(r"\b(missing|lack of|no|absent|without)\s+rate[- ]limit", re.I)),
        ("ReDoS (out of scope)", re.compile(r"\b(redos|regex(?:ular expression)? denial)\b", re.I)),
        ("Resource/handle leak (not a vulnerability)", re.compile(r"\b(unclosed|leak(?:ed|ing)?)\s+(?:file|socket|connection|handle|resource)s?\b", re.I)),
        ("Open redirect without chained impact (out of scope)", re.compile(r"\bopen redirect\b", re.I)),
    ]
    _MEMORY_SAFETY = re.compile(r"\b(buffer overflow|out[- ]of[- ]bounds|use[- ]after[- ]free|double[- ]free|null pointer dereference|memory corruption|integer overflow)\b", re.I)
    _MEMORY_UNSAFE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".zig", ".asm", ".s"}

    @classmethod
    def exclusion_reason(cls, finding: Dict[str, Any]) -> Optional[str]:
        path = str(finding.get("file") or "")
        if path.lower().endswith((".md", ".rst", ".txt", ".adoc")):
            return "Finding in documentation file"
        text = " ".join(str(finding.get(k) or "") for k in ("title", "category", "description")).lower()
        for reason, pattern in cls._PATTERNS:
            if pattern.search(text):
                # "open redirect" chained into token theft is allowed through
                if reason.startswith("Open redirect") and re.search(r"token|session|credential|oauth|code\b", text):
                    continue
                return reason
        ext = ("." + path.rsplit(".", 1)[-1].lower()) if "." in path.rsplit("/", 1)[-1] else ""
        if cls._MEMORY_SAFETY.search(text) and ext not in cls._MEMORY_UNSAFE_EXTENSIONS:
            return "Memory-safety finding in a memory-safe language"
        return None


@dataclass
class FilterSummary:
    total: int = 0
    kept: int = 0
    excluded_by_rule: int = 0
    excluded_low_confidence: int = 0
    excluded_directory: int = 0
    excluded_not_in_diff: int = 0
    merged_duplicates: int = 0
    excluded_details: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "kept": self.kept,
            "excluded_by_rule": self.excluded_by_rule,
            "excluded_low_confidence": self.excluded_low_confidence,
            "excluded_directory": self.excluded_directory,
            "excluded_not_in_diff": self.excluded_not_in_diff,
            "merged_duplicates": self.merged_duplicates,
            "excluded_details": self.excluded_details,
        }


def normalize_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce a model-produced finding into the canonical shape."""
    severity = str(raw.get("severity") or "MEDIUM").upper()
    if severity not in SEVERITIES:
        severity = "MEDIUM"
    try:
        confidence = float(raw.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    try:
        line = int(raw.get("line") or 1)
    except (TypeError, ValueError):
        line = 1
    path = str(raw.get("file") or "").strip().removeprefix("./")
    category = re.sub(r"[^a-z0-9_]+", "_", str(raw.get("category") or "security_issue").strip().lower()).strip("_") or "security_issue"
    title = str(raw.get("title") or "").strip()
    description = str(raw.get("description") or "").strip()
    if not title:
        title = (description.split(". ")[0][:120] or category.replace("_", " ").title())
    return {
        "file": path,
        "line": max(1, line),
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "exploit_scenario": str(raw.get("exploit_scenario") or "").strip(),
        "recommendation": str(raw.get("recommendation") or "").strip(),
        "confidence": round(max(0.0, min(1.0, confidence)), 2),
        "introduced_by_change": bool(raw.get("introduced_by_change", True)),
        "scan": str(raw.get("scan") or "unknown"),
        "scans": sorted({str(raw.get("scan") or "unknown")}),
    }


_STOPWORDS = {"the", "a", "an", "of", "in", "to", "is", "and", "or", "for", "with", "via", "on", "by", "from", "at", "this", "that"}


def _tokens(text: str) -> set:
    return {t for t in re.findall(r"[a-z0-9_]+", text.lower()) if t not in _STOPWORDS and len(t) > 2}


def _similar(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """Two findings are duplicates when they hit the same file within a few lines and talk about the same thing."""
    if a["file"] != b["file"]:
        return False
    if abs(a["line"] - b["line"]) > 3:
        return False
    if a["category"] == b["category"]:
        return True
    ta, tb = _tokens(a["title"] + " " + a["description"]), _tokens(b["title"] + " " + b["description"])
    if not ta or not tb:
        return False
    jaccard = len(ta & tb) / len(ta | tb)
    return jaccard >= 0.45


_SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def merge_duplicates(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    merged: List[Dict[str, Any]] = []
    merged_count = 0
    for f in findings:
        target = next((m for m in merged if _similar(m, f)), None)
        if target is None:
            merged.append(f)
            continue
        merged_count += 1
        target["scans"] = sorted(set(target["scans"]) | set(f["scans"]))
        if (_SEVERITY_RANK[f["severity"]], f["confidence"]) > (_SEVERITY_RANK[target["severity"]], target["confidence"]):
            # Keep the stronger write-up but remember every scan that saw it.
            scans = target["scans"]
            target.update({k: v for k, v in f.items() if k != "scans"})
            target["scans"] = scans
        else:
            target["confidence"] = max(target["confidence"], f["confidence"])
    return merged, merged_count


def process_findings(
    raw_findings: List[Dict[str, Any]],
    bundle: Optional[DiffBundle] = None,
    rules: Optional[ExclusionRules] = None,
    min_confidence: float = DEFAULT_MIN_FINDING_CONFIDENCE,
    require_in_diff: bool = True,
) -> Tuple[List[Dict[str, Any]], FilterSummary]:
    """Normalise, filter, dedupe, and sort findings. Returns ``(kept, summary)``."""
    summary = FilterSummary(total=len(raw_findings))
    rules = rules or ExclusionRules()
    diff_paths = set(bundle.paths) if bundle else set()
    kept: List[Dict[str, Any]] = []

    for raw in raw_findings:
        f = normalize_finding(raw)
        reason = HardExclusionRules.exclusion_reason(f)
        if reason:
            summary.excluded_by_rule += 1
            summary.excluded_details.append({**f, "excluded_reason": reason})
            continue
        if f["confidence"] < min_confidence:
            summary.excluded_low_confidence += 1
            summary.excluded_details.append({**f, "excluded_reason": f"Confidence {f['confidence']} below threshold {min_confidence}"})
            continue
        if rules.is_excluded(f["file"]):
            summary.excluded_directory += 1
            summary.excluded_details.append({**f, "excluded_reason": "File is in an excluded directory"})
            continue
        if diff_paths and f["file"] not in diff_paths:
            # Models sometimes echo the diff's a/ b/ prefixes; only strip them when that yields a real diff path.
            stripped = f["file"][2:] if f["file"].startswith(("a/", "b/")) else f["file"]
            if stripped in diff_paths:
                f["file"] = stripped
        if require_in_diff and diff_paths and f["file"] not in diff_paths:
            summary.excluded_not_in_diff += 1
            summary.excluded_details.append({**f, "excluded_reason": "File is not part of the reviewed diff"})
            continue
        kept.append(f)

    kept, summary.merged_duplicates = merge_duplicates(kept)
    kept.sort(key=lambda f: (-_SEVERITY_RANK[f["severity"]], -f["confidence"], f["file"], f["line"]))
    summary.kept = len(kept)
    logger.info(
        "Findings: %d raw -> %d kept (%d rule, %d low-confidence, %d excluded-dir, %d not-in-diff, %d merged)",
        summary.total, summary.kept, summary.excluded_by_rule, summary.excluded_low_confidence,
        summary.excluded_directory, summary.excluded_not_in_diff, summary.merged_duplicates,
    )
    return kept, summary


def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.get("severity", "MEDIUM")] = counts.get(f.get("severity", "MEDIUM"), 0) + 1
    return counts

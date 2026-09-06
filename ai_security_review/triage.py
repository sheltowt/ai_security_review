"""Triage: one structured model call that decides which scans to run."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ai_security_review.claude_client import ClaudeClient
from ai_security_review.constants import (
    DEFAULT_TRIAGE_CONFIDENCE_THRESHOLD,
    DEFAULT_TRIAGE_EFFORT,
    DEFAULT_TRIAGE_MODEL,
    TRIAGE_MAX_TOKENS,
)
from ai_security_review.diff import DiffBundle
from ai_security_review.logger import get_logger
from ai_security_review.prompts import TRIAGE_SCHEMA, build_triage_system_prompt, build_triage_user_prompt
from ai_security_review.scans import SCAN_ORDER

logger = get_logger(__name__)


@dataclass
class TriageResult:
    summary: str
    change_kind: str
    risk_level: str
    scans: Dict[str, Dict]                 # key -> {relevant, confidence, reason, focus}
    notes: str = ""
    model: Optional[str] = None
    selected_scans: List[str] = field(default_factory=list)
    skipped: bool = False                  # True when triage was bypassed (forced scans / --skip-triage)

    def ensure_selected(self, key: str, reason_suffix: str) -> bool:
        """Add ``key`` to the selected scans (once), noting why in that scan's triage reason."""
        if key in self.selected_scans:
            return False
        self.selected_scans.append(key)
        entry = self.scans.setdefault(key, {"relevant": False, "confidence": 0.0, "reason": "", "focus": []})
        entry["reason"] = f"{entry.get('reason') or ''} ({reason_suffix})".strip()
        return True

    def to_dict(self) -> Dict:
        return {
            "summary": self.summary,
            "change_kind": self.change_kind,
            "risk_level": self.risk_level,
            "scans": self.scans,
            "notes": self.notes,
            "model": self.model,
            "selected_scans": list(self.selected_scans),
            "skipped": self.skipped,
        }


def select_scans(scans: Dict[str, Dict], threshold: float = DEFAULT_TRIAGE_CONFIDENCE_THRESHOLD) -> List[str]:
    """Pick scans marked relevant with confidence at or above ``threshold``, in canonical order."""
    selected = []
    for key in SCAN_ORDER:
        entry = scans.get(key) or {}
        if entry.get("relevant") and float(entry.get("confidence", 0)) >= threshold:
            selected.append(key)
    return selected


def forced_triage(scan_keys: List[str], reason: str = "forced by configuration") -> TriageResult:
    scans = {
        key: {"relevant": key in scan_keys, "confidence": 1.0 if key in scan_keys else 0.0, "reason": reason, "focus": []}
        for key in SCAN_ORDER
    }
    return TriageResult(
        summary="Triage skipped; scans were selected explicitly.",
        change_kind="mixed",
        risk_level="medium",
        scans=scans,
        selected_scans=[k for k in SCAN_ORDER if k in scan_keys],
        skipped=True,
    )


def run_triage(
    client: ClaudeClient,
    bundle: DiffBundle,
    pr_context: Optional[Dict] = None,
    model: str = DEFAULT_TRIAGE_MODEL,
    effort: str = DEFAULT_TRIAGE_EFFORT,
    threshold: float = DEFAULT_TRIAGE_CONFIDENCE_THRESHOLD,
    custom_instructions: Optional[str] = None,
    tool_signals: Optional[str] = None,
) -> TriageResult:
    response = client.structured_call(
        model=model,
        system=build_triage_system_prompt(),
        user=build_triage_user_prompt(bundle, pr_context, custom_instructions, tool_signals=tool_signals),
        schema=TRIAGE_SCHEMA,
        max_tokens=TRIAGE_MAX_TOKENS,
        effort=effort,
        label="triage",
    )
    data = response.data if isinstance(response.data, dict) else {}
    scans = {key: dict((data.get("scans") or {}).get(key) or {}) for key in SCAN_ORDER}
    for key in SCAN_ORDER:
        scans[key].setdefault("relevant", False)
        scans[key].setdefault("confidence", 0.0)
        scans[key].setdefault("reason", "")
        scans[key].setdefault("focus", [])
    result = TriageResult(
        summary=str(data.get("summary", "")),
        change_kind=str(data.get("change_kind", "mixed")),
        risk_level=str(data.get("risk_level", "low")),
        scans=scans,
        notes=str(data.get("notes", "")),
        model=response.model,
        selected_scans=select_scans(scans, threshold),
    )
    logger.info(
        "Triage: risk=%s kind=%s selected=%s",
        result.risk_level,
        result.change_kind,
        ",".join(result.selected_scans) or "none",
    )
    return result

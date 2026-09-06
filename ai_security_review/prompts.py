"""Prompt builders for triage and the three scans."""

from typing import Dict, List, Optional

from ai_security_review.diff import DiffBundle
from ai_security_review.scans import SCAN_ORDER, SCAN_DEFINITIONS, ScanDefinition

# --------------------------------------------------------------------------------------
# Shared pieces
# --------------------------------------------------------------------------------------

GLOBAL_EXCLUSIONS = """Do NOT report any of the following, regardless of scan:
- Denial of service, resource exhaustion, missing rate limiting, memory/CPU consumption, ReDoS.
- Style, naming, code quality, missing tests, or documentation gaps.
- Theoretical issues with no realistic path from an attacker-controlled input to impact.
- Pre-existing problems in code that this change does not touch or materially worsen. The review is of the *change*.
- Findings in Markdown or plain documentation files.
- Memory-safety bugs in memory-safe languages.
- Open redirects unless chained into token theft."""

CONFIDENCE_RUBRIC = """Confidence scale:
- 0.9-1.0: the exploit path is clear from the code shown.
- 0.8-0.9: a well-known vulnerable pattern with a plausible input source.
- 0.7-0.8: suspicious, but exploitation depends on conditions you could not confirm.
- below 0.7: do not report."""


def _describe_change(pr_context: Optional[Dict], bundle: DiffBundle) -> str:
    lines: List[str] = []
    if pr_context:
        if pr_context.get("repo"):
            lines.append(f"Repository: {pr_context['repo']}")
        if pr_context.get("number"):
            lines.append(f"Pull request: #{pr_context['number']} \"{pr_context.get('title', '')}\"")
        if pr_context.get("author"):
            lines.append(f"Author: {pr_context['author']}")
        body = (pr_context.get("body") or "").strip()
        if body:
            lines.append("Description:\n" + body[:4000])
    lines.append(f"Files changed: {len(bundle.files)}")
    for f in bundle.files:
        lines.append(f"- {f.path} ({f.status}, +{f.additions}/-{f.deletions})")
    if bundle.excluded:
        lines.append(f"(Excluded from review: {', '.join(bundle.excluded[:20])})")
    if bundle.truncated:
        lines.append("NOTE: some large patches were truncated for size.")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Triage
# --------------------------------------------------------------------------------------

TRIAGE_SYSTEM = """You are a senior application security engineer triaging a code change before a detailed review.

Your job is routing, not auditing. Decide which of three specialised security scans should run on this change:

DATA     - {data_q}
EXPOSURE - {exposure_q}
ACCESS   - {access_q}

Mark a scan relevant when the change plausibly affects that area, even if you have not confirmed a bug. Mark it not relevant when the diff clearly cannot affect it (pure formatting, comments, tests of unrelated logic, docs, version bumps of dev-only tooling). When in doubt about a scan, lean toward running it, but say so with a lower confidence.

Do not report vulnerabilities yourself. Give each relevant scan a short, concrete focus list so it can start in the right place.
"""


def build_triage_system_prompt() -> str:
    return TRIAGE_SYSTEM.format(
        data_q=SCAN_DEFINITIONS["data"].question,
        exposure_q=SCAN_DEFINITIONS["exposure"].question,
        access_q=SCAN_DEFINITIONS["access"].question,
    )


def build_triage_user_prompt(bundle: DiffBundle, pr_context: Optional[Dict] = None, custom_instructions: Optional[str] = None) -> str:
    hints = "\n".join(
        f"- {SCAN_DEFINITIONS[k].key.upper()} is relevant when: {SCAN_DEFINITIONS[k].triage_hint}" for k in SCAN_ORDER
    )
    custom = f"\nADDITIONAL TRIAGE INSTRUCTIONS:\n{custom_instructions.strip()}\n" if custom_instructions else ""
    return f"""CHANGE SUMMARY
{_describe_change(pr_context, bundle)}

RELEVANCE CRITERIA
{hints}
{custom}
DIFF
```diff
{bundle.text}
```

Triage this change. For each scan, decide whether it should run, how confident you are (0-1), why, and where it should focus (file paths plus a phrase, e.g. "api/users.py: new /export endpoint returns full user rows"). Also give an overall risk level and a two-sentence summary of what the change does.
"""


TRIAGE_SCHEMA: Dict = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "Two sentences: what the change does and why it matters for security."},
        "change_kind": {
            "type": "string",
            "enum": ["feature", "bugfix", "refactor", "config", "infrastructure", "dependency", "test", "docs", "mixed"],
        },
        "risk_level": {"type": "string", "enum": ["none", "low", "medium", "high"]},
        "scans": {
            "type": "object",
            "properties": {
                key: {
                    "type": "object",
                    "properties": {
                        "relevant": {"type": "boolean"},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "reason": {"type": "string"},
                        "focus": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["relevant", "confidence", "reason", "focus"],
                    "additionalProperties": False,
                }
                for key in SCAN_ORDER
            },
            "required": list(SCAN_ORDER),
            "additionalProperties": False,
        },
        "notes": {"type": "string", "description": "Anything the scans should know: frameworks in use, trust assumptions, areas that look pre-existing."},
    },
    "required": ["summary", "change_kind", "risk_level", "scans", "notes"],
    "additionalProperties": False,
}


# --------------------------------------------------------------------------------------
# Scans
# --------------------------------------------------------------------------------------

SCAN_SYSTEM = """You are a senior application security engineer performing the {title} scan of a code change.

THE ONE QUESTION THIS SCAN ANSWERS
{question}

IN SCOPE
{in_scope}

CATEGORIES TO USE (pick the closest; invent a snake_case name only if none fits)
{categories}

CODE-LEVEL SIGNALS WORTH CHECKING
{signals}

OUT OF SCOPE - OTHER SCANS COVER THESE
{hand_off}

{global_exclusions}

{confidence_rubric}

HOW TO WORK
1. Read the triage focus first and start there, then cover the rest of the diff.
2. For each candidate, trace the data or control flow from an attacker-reachable input to the impact. If you cannot find a realistic source or sink, do not report it.
3. Report only issues that are introduced or materially worsened by this change. Set introduced_by_change=false only when you are flagging pre-existing code that the change makes reachable in a new way.
4. Line numbers refer to the post-change file (the '+' side of the diff).
5. Prefer fewer, well-evidenced findings over an exhaustive list. A security engineer should be able to raise each finding in review without embarrassment.

Severity: HIGH = directly exploitable with serious impact (data breach, account takeover, RCE, cross-tenant access). MEDIUM = exploitable under specific but realistic conditions. LOW = defense-in-depth with limited impact.
"""


def build_scan_system_prompt(scan: ScanDefinition, custom_instructions: Optional[str] = None) -> str:
    text = SCAN_SYSTEM.format(
        title=scan.title,
        question=scan.question,
        in_scope="\n".join(f"- {s}" for s in scan.in_scope),
        categories=", ".join(scan.categories),
        signals="\n".join(f"- {s}" for s in scan.signals),
        hand_off="\n".join(f"- {SCAN_DEFINITIONS[k].title} scan: {why}" for k, why in scan.hand_off.items()),
        global_exclusions=GLOBAL_EXCLUSIONS,
        confidence_rubric=CONFIDENCE_RUBRIC,
    )
    if custom_instructions:
        text += f"\nPROJECT-SPECIFIC INSTRUCTIONS FOR THIS SCAN\n{custom_instructions.strip()}\n"
    return text


def build_scan_user_prompt(
    scan: ScanDefinition,
    bundle: DiffBundle,
    triage: Dict,
    pr_context: Optional[Dict] = None,
    context_files: Optional[Dict[str, str]] = None,
    repo_exploration_available: bool = False,
) -> str:
    scan_triage = (triage.get("scans") or {}).get(scan.key, {})
    focus = scan_triage.get("focus") or []
    focus_text = "\n".join(f"- {f}" for f in focus) if focus else "- (no specific focus given; review the whole diff)"

    parts: List[str] = [
        "CHANGE SUMMARY",
        _describe_change(pr_context, bundle),
        "",
        "TRIAGE",
        f"Summary: {triage.get('summary', '')}",
        f"Risk level: {triage.get('risk_level', 'unknown')} | Change kind: {triage.get('change_kind', 'unknown')}",
        f"Why this scan was selected: {scan_triage.get('reason', '')}",
        f"Focus areas:\n{focus_text}",
    ]
    if triage.get("notes"):
        parts.append(f"Triage notes: {triage['notes']}")

    parts += ["", "DIFF", "```diff", bundle.text, "```"]

    if context_files:
        parts += ["", "POST-CHANGE CONTENTS OF TOUCHED FILES (for context; the diff above is what is under review)"]
        for path, content in context_files.items():
            parts += [f"\n===== {path} =====", content]

    if repo_exploration_available:
        parts += [
            "",
            "You have read-only tools to explore the repository. Use them to confirm how inputs reach the changed code, "
            "what sanitisation or authorisation wrappers already exist, and whether the surrounding framework already mitigates a candidate finding.",
        ]

    parts += [
        "",
        f"Perform the {scan.title} scan now. Output findings using the required JSON schema. "
        "If there are no findings that meet the bar, return an empty findings list and explain briefly in notes what you checked.",
    ]
    return "\n".join(parts)


def scan_output_instructions_for_cli(schema_json: str) -> str:
    """Appended when running through Claude Code, which cannot enforce output_config."""
    return f"""
REQUIRED OUTPUT
Your final message must be a single JSON object matching this schema and nothing else - no prose before or after, no code fence:
{schema_json}
"""

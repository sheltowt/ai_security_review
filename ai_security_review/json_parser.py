"""Tolerant JSON extraction from model output."""

import json
import re
from typing import Any, Optional, Tuple


def extract_json_from_text(text: str) -> Optional[Any]:
    """Find and parse a JSON object in free text.

    Tries, in order: the whole string, fenced ```json blocks, fenced ``` blocks,
    then the first balanced ``{...}`` span that parses.
    """
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass

    for pattern in (r"```json\s*(.*?)\s*```", r"```\s*(\{.*?\})\s*```"):
        match = re.search(pattern, text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                continue

    depth = 0
    start = -1
    in_string = False
    escape = False
    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth == 0:
                continue
            depth -= 1
            if depth == 0 and start != -1:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    start = -1
                    continue
    return None


def parse_json_with_fallbacks(text: str, context: str = "") -> Tuple[bool, Any]:
    """Return ``(True, obj)`` on success or ``(False, {"error": ...})``."""
    parsed = extract_json_from_text(text)
    if parsed is not None:
        return True, parsed
    prefix = f"{context}: " if context else ""
    return False, {"error": f"{prefix}could not parse JSON from model output", "raw": (text or "")[:2000]}

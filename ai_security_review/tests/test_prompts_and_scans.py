import json

from ai_security_review.diff import build_bundle
from ai_security_review.prompts import (
    TRIAGE_SCHEMA,
    build_scan_system_prompt,
    build_scan_user_prompt,
    build_triage_system_prompt,
    build_triage_user_prompt,
)
from ai_security_review.scans import ACCESS_SCAN, DATA_SCAN, EXPOSURE_SCAN, SCAN_DEFINITIONS, SCAN_RESULT_SCHEMA, get_scan


def test_scan_definitions_are_distinct():
    keys = list(SCAN_DEFINITIONS)
    assert keys == ["data", "exposure", "access"]
    # No category should belong to two scans
    seen = {}
    for scan in SCAN_DEFINITIONS.values():
        for cat in scan.categories:
            assert cat not in seen, f"{cat} in both {seen.get(cat)} and {scan.key}"
            seen[cat] = scan.key
    # Every scan hands off to both siblings
    for scan in SCAN_DEFINITIONS.values():
        assert set(scan.hand_off) == set(keys) - {scan.key}


def test_get_scan_unknown():
    try:
        get_scan("network")
    except ValueError as e:
        assert "Unknown scan" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_schemas_are_strict_json():
    for schema in (TRIAGE_SCHEMA, SCAN_RESULT_SCHEMA):
        json.dumps(schema)
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])
    assert set(TRIAGE_SCHEMA["properties"]["scans"]["required"]) == {"data", "exposure", "access"}


def test_triage_prompts_mention_all_scans(sample_diff):
    bundle = build_bundle(sample_diff)
    system = build_triage_system_prompt()
    user = build_triage_user_prompt(bundle, {"repo": "o/r", "number": 7, "title": "Export", "author": "dev"}, custom_instructions="Treat billing as high risk.")
    for word in ("DATA", "EXPOSURE", "ACCESS"):
        assert word in system and word in user
    assert "Pull request: #7" in user
    assert "Treat billing as high risk." in user
    assert "export_user" in user  # diff included


def test_scan_prompt_includes_focus_and_handoffs(sample_diff, helpers):
    bundle = build_bundle(sample_diff)
    triage = helpers["triage_payload"]()
    system = build_scan_system_prompt(DATA_SCAN, custom_instructions="Ignore test fixtures.")
    user = build_scan_user_prompt(DATA_SCAN, bundle, triage, context_files={"app/api/users.py": "FULL FILE"})
    assert DATA_SCAN.question in system
    assert "Exposure scan:" in system and "Access control scan:" in system
    assert "Ignore test fixtures." in system
    assert "export_user query" in user
    assert "FULL FILE" in user
    assert "read-only tools" not in user
    cli_user = build_scan_user_prompt(ACCESS_SCAN, bundle, triage, repo_exploration_available=True)
    assert "read-only tools" in cli_user


def test_each_scan_has_signals_and_scope():
    for scan in (DATA_SCAN, EXPOSURE_SCAN, ACCESS_SCAN):
        assert len(scan.in_scope) >= 5
        assert len(scan.signals) >= 5
        assert scan.triage_hint

"""How scanner output flows through triage, the scans, candidate resolution, and the report."""

import json

import pytest

from ai_security_review.cli import build_parser
from ai_security_review.constants import BACKEND_API, UNVERIFIED_CANDIDATE_MAX_CONFIDENCE
from ai_security_review.diff import build_bundle
from ai_security_review.findings import HardExclusionRules, collapse_candidates, merge_duplicates, normalize_finding, process_findings, resolve_candidates
from ai_security_review.pipeline import PipelineConfig, run_pipeline
from ai_security_review.prompts import build_scan_user_prompt, build_triage_user_prompt, describe_tool_signals
from ai_security_review.report import finding_comment_body, render_markdown_summary
from ai_security_review.scan_runner import ScanRunner
from ai_security_review.scans import DATA_SCAN, SCAN_RESULT_SCHEMA
from ai_security_review.tools import ToolResult


def _secret(line=13, category="hardcoded_secret", **kw):
    f = {
        "file": "app/api/users.py", "line": line, "severity": "HIGH", "category": category,
        "title": "Hardcoded secret (aws-access-token)", "description": "gitleaks matched rule 'aws-access-token'.",
        "exploit_scenario": "Anyone with repo access can use it.", "recommendation": "Rotate.",
        "confidence": 0.85, "introduced_by_change": True, "scan": "gitleaks", "tool": "gitleaks", "rule_id": "aws-access-token",
    }
    f.update(kw)
    return f


def _candidate(id="semgrep-1", line=15, category="sql_injection", owner="data", confidence=0.45, rule="python.lang.sql", **kw):
    c = {
        "id": id, "file": "app/api/users.py", "line": line, "end_line": line, "severity": "MEDIUM", "category": category,
        "title": f"{category} ({rule})", "description": f"Semgrep rule '{rule}' matched.", "exploit_scenario": "",
        "recommendation": "See docs.", "confidence": confidence, "introduced_by_change": True,
        "scan": "semgrep", "tool": "semgrep", "rule_id": rule, "owner_scan": owner, "snippet": "db.execute(f'...')", "cwe": ["CWE-89"],
    }
    c.update(kw)
    return c


def _tool_results(findings=(), candidates=()):
    return [
        ToolResult(tool="gitleaks", status="completed", version="8.30.1", findings=list(findings), notes="ok"),
        ToolResult(tool="semgrep", status="completed", version="1.176.1", candidates=list(candidates), notes="ok"),
    ]


def _config(tmp_path, **kw):
    return PipelineConfig(repo_dir=tmp_path, backend=BACKEND_API, include_context_files=False, tools=["gitleaks", "semgrep"], **kw)


# ---- prompts and schema ------------------------------------------------------------


def test_schema_has_candidate_verdicts():
    assert "candidate_verdicts" in SCAN_RESULT_SCHEMA["required"]
    assert SCAN_RESULT_SCHEMA["properties"]["candidate_verdicts"]["items"]["properties"]["verdict"]["enum"] == ["confirmed", "dismissed", "unsure"]


def test_tool_signals_in_triage_prompt(bundle):
    signals = describe_tool_signals([_secret()], [_candidate()])
    assert "[gitleaks] app/api/users.py:13 hardcoded_secret" in signals
    assert "[semgrep candidate, data scan] app/api/users.py:15 sql_injection" in signals
    assert describe_tool_signals([], []) == ""
    assert "... 2 more" in describe_tool_signals([_secret(line=i) for i in range(5)], [], limit=3)
    user = build_triage_user_prompt(bundle, tool_signals=signals)
    assert "SCANNER SIGNALS" in user and "routing hints" in user
    assert "SCANNER SIGNALS" not in build_triage_user_prompt(bundle)


def test_candidates_and_reported_in_scan_prompt(bundle, helpers):
    triage = helpers["triage_payload"]()
    user = build_scan_user_prompt(DATA_SCAN, bundle, triage, candidates=[_candidate()], reported_by_tools=[_secret()])
    assert "SCANNER CANDIDATES" in user and "[semgrep-1] app/api/users.py:15 sql_injection via semgrep rule python.lang.sql" in user
    assert "matched source:" in user and "db.execute" in user
    assert "ALREADY REPORTED BY SCANNERS" in user and "hardcoded_secret" in user
    plain = build_scan_user_prompt(DATA_SCAN, bundle, triage)
    assert "SCANNER CANDIDATES" not in plain and "ALREADY REPORTED" not in plain


def test_scan_runner_routes_candidates_to_owner(tmp_path, bundle, fake_client_factory, helpers):
    client = fake_client_factory({"scan": helpers["scan_payload"]([], [{"id": "semgrep-1", "verdict": "confirmed", "reason": "no sanitising"}])})
    runner = ScanRunner(repo_dir=tmp_path, backend=BACKEND_API, client=client, include_context_files=False)
    results = runner.run_all(["data", "exposure"], bundle, helpers["triage_payload"](), candidates=[_candidate(owner="data")], tool_findings=[_secret()])
    prompts = {c["label"]: c["user"] for c in client.calls}
    assert "SCANNER CANDIDATES" in prompts["scan:data"] and "SCANNER CANDIDATES" not in prompts["scan:exposure"]
    assert "ALREADY REPORTED" in prompts["scan:exposure"] and "ALREADY REPORTED" not in prompts["scan:data"]
    assert results[0].candidate_verdicts == [{"id": "semgrep-1", "verdict": "confirmed", "reason": "no sanitising"}]
    assert results[0].to_dict()["candidate_verdicts"][0]["verdict"] == "confirmed"


def test_scan_runner_cleans_verdicts(tmp_path, bundle, fake_client_factory, helpers):
    payload = helpers["scan_payload"]([], [{"id": "x", "verdict": "MAYBE"}, {"verdict": "confirmed"}, "junk"])
    client = fake_client_factory({"scan": payload})
    runner = ScanRunner(repo_dir=tmp_path, backend=BACKEND_API, client=client, include_context_files=False)
    result = runner.run_one("data", bundle, helpers["triage_payload"]())
    assert result.candidate_verdicts == [{"id": "x", "verdict": "unsure", "reason": ""}]


# ---- findings stage ----------------------------------------------------------------


def test_secret_in_docs_is_not_excluded():
    assert HardExclusionRules.exclusion_reason(normalize_finding(_secret(file="README.md"))) is None
    assert HardExclusionRules.exclusion_reason(normalize_finding(_secret(file="README.md", category="secret_in_history"))) is None
    assert HardExclusionRules.exclusion_reason(normalize_finding(_secret(file="README.md", category="xss_reflected"))) == "Finding in documentation file"


def test_normalize_keeps_tool_provenance():
    f = normalize_finding(_secret(scans=["gitleaks", "exposure"], cwe=["CWE-798"]))
    assert f["scans"] == ["exposure", "gitleaks"] and f["tool"] == "gitleaks" and f["rule_id"] == "aws-access-token" and f["cwe"] == ["CWE-798"]
    assert "tool" not in normalize_finding({"file": "a.py", "scan": "data"})


def test_merge_keeps_rule_when_model_writeup_wins():
    tool = normalize_finding(_secret(confidence=0.85))
    model = normalize_finding({**_secret(), "scan": "exposure", "confidence": 0.95, "title": "AWS key committed", "description": "Key is live."})
    del model["tool"], model["rule_id"]
    merged, count = merge_duplicates([tool, model])
    assert count == 1 and merged[0]["title"] == "AWS key committed"
    assert merged[0]["scans"] == ["exposure", "gitleaks"] and merged[0]["rule_id"] == "aws-access-token"


def test_resolve_candidates_verdicts():
    cands = [
        _candidate(id="semgrep-1"),                                   # confirmed
        _candidate(id="semgrep-2", line=16),                          # dismissed
        _candidate(id="semgrep-3", line=17),                          # unsure -> capped
        _candidate(id="semgrep-4", line=18, confidence=0.8),          # no verdict, high rule confidence -> still capped
        _candidate(id="semgrep-5", line=19),                          # no verdict, low confidence -> capped
    ]
    verdicts = {
        "semgrep-1": {"id": "semgrep-1", "verdict": "confirmed", "reason": "q reaches the query", "scan": "data"},
        "semgrep-2": {"id": "semgrep-2", "verdict": "dismissed", "reason": "constant input", "scan": "data"},
        "semgrep-3": {"id": "semgrep-3", "verdict": "unsure", "reason": "could not trace", "scan": "data"},
    }
    findings, excluded, counts = resolve_candidates(cands, verdicts)
    assert counts == {"total": 5, "confirmed": 1, "dismissed": 1, "unverified": 3}
    assert [f["line"] for f in findings] == [15, 17, 18, 19]
    confirmed = findings[0]
    assert confirmed["confidence"] == 0.85 and sorted(confirmed["scans"]) == ["data", "semgrep"]
    assert "Confirmed by the data scan: q reaches the query" in confirmed["description"]
    assert "owner_scan" not in confirmed and "snippet" not in confirmed and "id" not in confirmed
    # Unverified candidates never exceed the cap, whatever the rule claimed, and say why
    for f in findings[1:]:
        assert f["confidence"] <= UNVERIFIED_CANDIDATE_MAX_CONFIDENCE and f["scans"] == ["semgrep"]
    assert "could not confirm or rule this out: could not trace" in findings[1]["description"]
    assert "No scan verified this scanner candidate" in findings[2]["description"]
    assert [e["excluded_reason"] for e in excluded] == ["Dismissed by the data scan: constant input"]
    # The single threshold pass in process_findings is what keeps unverified candidates out
    kept, summary = process_findings(findings, None, None, 0.7)
    assert [k["line"] for k in kept] == [15]
    assert summary.excluded_low_confidence == 3


def test_collapse_candidates():
    reported = [_secret(line=13)]
    cands = [
        _candidate(id="a", line=13, category="hardcoded_secret", owner="exposure"),   # already reported by gitleaks
        _candidate(id="b", line=15, rule="r.one"),
        _candidate(id="c", line=16, rule="r.two", confidence=0.6),                    # same category within 3 lines -> folded
        _candidate(id="d", line=40, rule="r.three"),
    ]
    kept, dropped = collapse_candidates(cands, reported)
    assert dropped == 2
    assert [c["id"] for c in kept] == ["semgrep-1", "semgrep-2"]
    assert kept[0]["rule_id"] == "r.one, r.two" and kept[0]["confidence"] == 0.6 and "r.two" in kept[0]["description"]
    assert collapse_candidates([], []) == ([], 0)


# ---- pipeline ----------------------------------------------------------------------


def test_pipeline_reports_tool_findings_and_verifies_candidates(tmp_path, bundle, fake_client_factory, helpers, monkeypatch):
    monkeypatch.setattr("ai_security_review.pipeline.run_tools", lambda *a, **kw: _tool_results(
        findings=[_secret()],
        candidates=[_candidate(id="semgrep-1"), _candidate(id="semgrep-2", line=16, category="command_injection", rule="r.cmd"),
                    _candidate(id="semgrep-3", line=16, category="csrf", owner="access")],
    ))
    client = fake_client_factory({
        "triage": helpers["triage_payload"](data=True, exposure=False, access=False),
        "scan:data": helpers["scan_payload"](
            [helpers["finding"]()],   # the model's own write-up of the same SQL injection
            [{"id": "semgrep-1", "verdict": "confirmed", "reason": "q is user input"}, {"id": "semgrep-2", "verdict": "dismissed", "reason": "argument is constant"}],
        ),
        "scan:access": helpers["scan_payload"]([], [{"id": "semgrep-3", "verdict": "unsure", "reason": "framework unclear"}]),
    })
    result = run_pipeline(_config(tmp_path), bundle, client=client)

    triage_user = client.calls[0]["user"]
    assert "SCANNER SIGNALS" in triage_user and "[gitleaks] app/api/users.py:13 hardcoded_secret" in triage_user
    assert result["triage"]["selected_scans"] == ["data", "access"]
    assert "(added to verify scanner candidates)" in result["triage"]["scans"]["access"]["reason"]
    assert [t["tool"] for t in result["tool_results"]] == ["gitleaks", "semgrep"]

    by_cat = {f["category"]: f for f in result["findings"]}
    assert set(by_cat) == {"hardcoded_secret", "sql_injection"}
    assert by_cat["hardcoded_secret"]["scans"] == ["gitleaks"] and by_cat["hardcoded_secret"]["rule_id"] == "aws-access-token"
    sql = by_cat["sql_injection"]
    assert sql["title"] == "SQL injection in export_user"                 # the model write-up won the merge
    assert sql["scans"] == ["data", "semgrep"] and sql["rule_id"] == "python.lang.sql"

    filt = result["filter_summary"]
    assert (filt["candidates_total"], filt["candidates_confirmed"], filt["candidates_dismissed"], filt["candidates_unverified"]) == (3, 1, 1, 1)
    reasons = [e["excluded_reason"] for e in filt["excluded_details"]]
    assert any(r.startswith("Dismissed by the data scan: argument is constant") for r in reasons)
    unsure = next(e for e in filt["excluded_details"] if e["category"] == "csrf")
    assert unsure["excluded_reason"].startswith("Confidence") and "could not confirm or rule this out: framework unclear" in unsure["description"]
    json.dumps(result)

    md = render_markdown_summary(result)
    assert "### Scanners" in md and "| gitleaks | ✅ ran | 8.30.1 | 1 | 0 |" in md
    assert "3 scanner candidate(s): 1 confirmed, 1 dismissed, 1 unverified" in md
    body = finding_comment_body(sql)
    assert "**Found by:** data, semgrep" in body and "**Rule:** `python.lang.sql`" in body


def test_pipeline_tool_findings_survive_triage_failure(tmp_path, bundle, fake_client_factory, monkeypatch):
    monkeypatch.setattr("ai_security_review.pipeline.run_tools", lambda *a, **kw: _tool_results(findings=[_secret()]))
    client = fake_client_factory({}, fail_labels=["triage"])
    result = run_pipeline(_config(tmp_path), bundle, client=client)
    assert result["error"].startswith("Triage failed")
    assert [f["category"] for f in result["findings"]] == ["hardcoded_secret"]


def test_pipeline_forced_scans_drop_unowned_candidates(tmp_path, bundle, fake_client_factory, helpers, monkeypatch):
    monkeypatch.setattr("ai_security_review.pipeline.run_tools", lambda *a, **kw: _tool_results(candidates=[_candidate(confidence=0.8)]))
    client = fake_client_factory({"scan": helpers["scan_payload"]([])})
    result = run_pipeline(_config(tmp_path, forced_scans=["exposure"]), bundle, client=client)
    assert [c["label"] for c in client.calls] == ["scan:exposure"]
    # The data scan was not forced, so its candidate gets no verdict and is not reported on the rule alone
    assert result["findings"] == []
    assert "SCANNER CANDIDATES" not in client.calls[0]["user"]
    fs = result["filter_summary"]
    assert fs["candidates_total"] == 1 and fs["candidates_unverified"] == 1
    assert "not among the forced scans" in fs["excluded_details"][0]["excluded_reason"]


def test_pipeline_unverified_candidate_needs_lower_threshold(tmp_path, bundle, fake_client_factory, helpers, monkeypatch):
    """A scan that ran but gave no verdict leaves the candidate capped; only a lower --min-confidence shows it."""
    monkeypatch.setattr("ai_security_review.pipeline.run_tools", lambda *a, **kw: _tool_results(candidates=[_candidate(confidence=0.8)]))
    triage = helpers["triage_payload"](data=True, exposure=False, access=False)
    client = fake_client_factory({"triage": triage, "scan": helpers["scan_payload"]([])})
    result = run_pipeline(_config(tmp_path), bundle, client=client)
    assert result["findings"] == [] and result["filter_summary"]["candidates_unverified"] == 1
    client = fake_client_factory({"triage": triage, "scan": helpers["scan_payload"]([])})
    result = run_pipeline(_config(tmp_path, min_confidence=0.5), bundle, client=client)
    assert [f["category"] for f in result["findings"]] == ["sql_injection"]
    assert result["findings"][0]["confidence"] == UNVERIFIED_CANDIDATE_MAX_CONFIDENCE


def test_pipeline_triage_failure_still_reports_tool_output(tmp_path, bundle, fake_client_factory, helpers, monkeypatch):
    secret = _secret()
    monkeypatch.setattr("ai_security_review.pipeline.run_tools", lambda *a, **kw: _tool_results(findings=[secret], candidates=[_candidate(confidence=0.9)]))
    client = fake_client_factory({}, fail_labels=["triage"])
    result = run_pipeline(_config(tmp_path), bundle, client=client)
    assert result["error"].startswith("Triage failed")
    assert [f["category"] for f in result["findings"]] == ["hardcoded_secret"]
    fs = result["filter_summary"]
    assert fs["candidates_total"] == 1 and fs["candidates_unverified"] == 1
    assert any("No scan verified" in e.get("description", "") for e in fs["excluded_details"])


def test_pipeline_skipped_tools_render(tmp_path, bundle, fake_client_factory, helpers, monkeypatch):
    monkeypatch.setattr("ai_security_review.pipeline.run_tools", lambda *a, **kw: [
        ToolResult(tool="gitleaks", status="skipped", notes="'gitleaks' not found on PATH"),
        ToolResult(tool="semgrep", status="failed", error="timed out after 300s"),
    ])
    client = fake_client_factory({"triage": helpers["triage_payload"](data=False, exposure=False, access=False)})
    result = run_pipeline(_config(tmp_path), bundle, client=client)
    assert result["findings"] == [] and result["error"] is None
    md = render_markdown_summary(result)
    assert "| gitleaks | — skipped |" in md and "| semgrep | ❌ failed |" in md and "timed out" in md


def test_pipeline_default_tools_disabled_in_tests(tmp_path, bundle, fake_client_factory, helpers):
    """The autouse fixture blanks the default tool list so developer machines with gitleaks installed stay deterministic."""
    client = fake_client_factory({"triage": helpers["triage_payload"](data=False, exposure=False, access=False)})
    result = run_pipeline(PipelineConfig(repo_dir=tmp_path, backend=BACKEND_API, include_context_files=False), bundle, client=client)
    assert result["tool_results"] == []


@pytest.mark.external_tools
def test_pipeline_runs_real_tools_when_installed(tmp_path, bundle, fake_client_factory, helpers):
    """Exercises the real adapters end to end; each is skipped (not failed) when its binary is absent."""
    client = fake_client_factory({"triage": helpers["triage_payload"](data=False, exposure=False, access=False), "scan": helpers["scan_payload"]([])})
    result = run_pipeline(_config(tmp_path), bundle, client=client)
    assert {t["tool"]: t["status"] for t in result["tool_results"]}.keys() == {"gitleaks", "semgrep"}
    assert all(t["status"] in ("completed", "skipped") for t in result["tool_results"])


# ---- CLI ---------------------------------------------------------------------------


def test_cli_tool_flags(monkeypatch):
    monkeypatch.setattr("ai_security_review.cli.DEFAULT_TOOLS", ("gitleaks", "semgrep"))
    parser = build_parser()
    assert parser.parse_args(["--tools", "gitleaks"]).tools == ["gitleaks"]
    assert parser.parse_args(["--tools", "none"]).tools == []
    assert parser.parse_args(["--tools", "Semgrep, gitleaks", "--semgrep-config", "p/ci"]).semgrep_config == "p/ci"
    assert parser.parse_args([]).tools == ["gitleaks", "semgrep"]
    with pytest.raises(SystemExit):
        parser.parse_args(["--tools", "snyk"])


def test_cli_tools_env_var_none(monkeypatch):
    monkeypatch.setenv("AI_SECURITY_REVIEW_TOOLS", "none")
    assert build_parser().parse_args([]).tools == []


def test_pipeline_config_runs_no_tools_by_default(tmp_path):
    assert PipelineConfig(repo_dir=tmp_path).tools == []


# ---- follow-ups from the post-merge review -------------------------------------------------


def test_open_redirect_suppressed_at_intake():
    from ai_security_review.tools.categories import CWE_TO_CATEGORY, _EXTRA_OWNERS, is_suppressed, owner_scan

    assert is_suppressed(["CWE-601: URL Redirection to Untrusted Site"])
    assert 601 not in CWE_TO_CATEGORY
    # ownership has a single source: nothing in the extra map duplicates a ScanDefinition category
    assert not any(owner_scan(cat) != owner for cat, owner in _EXTRA_OWNERS.items())
    assert "secret_in_history" not in _EXTRA_OWNERS and owner_scan("secret_in_history") == "exposure"


def test_secret_categories_single_source():
    from ai_security_review.constants import SECRET_CATEGORIES
    from ai_security_review.findings import HardExclusionRules

    for cat in SECRET_CATEGORIES:
        assert HardExclusionRules.exclusion_reason({"file": "docs/setup.md", "category": cat, "description": "x"}) is None
    assert HardExclusionRules.exclusion_reason({"file": "docs/setup.md", "category": "xss_dom", "description": "x"})


def test_ensure_selected_is_idempotent():
    from ai_security_review.triage import forced_triage

    t = forced_triage(["data"])
    assert t.ensure_selected("access", "always-run") is True
    assert t.ensure_selected("access", "again") is False
    assert t.selected_scans == ["data", "access"]
    assert t.scans["access"]["reason"].endswith("(always-run)")


def test_history_finding_renders_without_preexisting_footnote():
    from ai_security_review.tools.gitleaks import GitleaksTool

    f = normalize_finding(GitleaksTool()._history_finding({"Description": "AWS key"}, "cfg.py", "aws-access-token", 2))
    assert f["introduced_by_change"] is True
    assert "Pre-existing code" not in finding_comment_body(f)


def test_gitleaksignore_prefixed_for_both_trees(tmp_path):
    from ai_security_review.tools.gitleaks import GitleaksTool

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "cfg.py").write_text("x = 1\n")
    (repo / ".gitleaksignore").write_text("# comment\ncfg.py:aws-access-token:2\n")
    diff = "diff --git a/cfg.py b/cfg.py\n--- a/cfg.py\n+++ b/cfg.py\n@@ -1 +1 @@\n-old\n+x = 1\n"
    bundle = build_bundle(diff)
    root = tmp_path / "stage"
    root.mkdir()
    GitleaksTool()._stage_files(root, repo, GitleaksTool.present_files(repo, bundle), bundle)
    lines = (root / ".gitleaksignore").read_text().splitlines()
    assert lines == ["# comment", "cfg.py:aws-access-token:2", "added/cfg.py:aws-access-token:2", "removed/cfg.py:aws-access-token:2"]

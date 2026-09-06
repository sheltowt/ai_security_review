"""Scanner adapters, driven by canned process output so no binary is needed."""

import json
import subprocess
from pathlib import Path

import pytest

from ai_security_review.diff import build_bundle
from ai_security_review.tools import GitleaksTool, SemgrepTool, ToolResult, get_tool, run_tools
from ai_security_review.tools.base import Tool, ToolError, read_snippet
from ai_security_review.tools.categories import category_for_cwes, cwe_numbers, is_suppressed, owner_scan
from ai_security_review.tools.gitleaks import removed_lines_with_positions
from ai_security_review.tools.semgrep import category_title

SECRETS_DIFF = """diff --git a/app/config.py b/app/config.py
index 1111111..2222222 100644
--- a/app/config.py
+++ b/app/config.py
@@ -1,4 +1,4 @@
 import os
-OLD_TOKEN = "ghp_removedremovedremovedremovedremoved00"
+AWS_KEY = "AKIAQ4T5RXKR2AB7ZZZZ"
 DEBUG = False
 TIMEOUT = 30
diff --git a/docs/setup.md b/docs/setup.md
index 3333333..4444444 100644
--- a/docs/setup.md
+++ b/docs/setup.md
@@ -1,1 +1,2 @@
 # Setup
+export API_KEY=sk-live-notreallyakeybutlongenough000000
"""

CONFIG_PY = 'import os\nAWS_KEY = "AKIAQ4T5RXKR2AB7ZZZZ"\nDEBUG = False\nTIMEOUT = 30\n'


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _repo(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "config.py").write_text(CONFIG_PY)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "setup.md").write_text("# Setup\nexport API_KEY=sk-live-notreallyakeybutlongenough000000\n")
    return tmp_path


# ---- base ---------------------------------------------------------------------------


def test_missing_binary_is_skipped(tmp_path, bundle, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    result = GitleaksTool().run(tmp_path, bundle)
    assert result.status == "skipped"
    assert "not found" in result.notes
    assert result.findings == []


def test_tool_crash_and_timeout_become_failed(tmp_path, bundle, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)

    class Boom(Tool):
        key = "boom"
        binaries = ("boom",)

        def scan(self, exe, repo_dir, bundle):
            raise subprocess.TimeoutExpired(cmd="boom", timeout=1)

    class Bad(Tool):
        key = "bad"
        binaries = ("bad",)

        def scan(self, exe, repo_dir, bundle):
            raise ToolError("exploded")

    assert Boom().run(tmp_path, bundle).status == "failed"
    assert "timed out" in Boom().run(tmp_path, bundle).error
    assert Bad().run(tmp_path, bundle).error == "exploded"


def test_read_snippet_bounds(tmp_path):
    (tmp_path / "f.py").write_text("a\nb\nc\nd\n")
    assert read_snippet(tmp_path, "f.py", 2, 3) == "b\nc"
    assert read_snippet(tmp_path, "missing.py", 1, 1) == ""


def test_removed_lines_positions():
    f = build_bundle(SECRETS_DIFF).files[0]
    lines, positions = removed_lines_with_positions(f)
    assert lines == ['OLD_TOKEN = "ghp_removedremovedremovedremovedremoved00"']
    assert positions == [2]           # removed where new-side line 2 now sits


# ---- categories ---------------------------------------------------------------------


def test_cwe_mapping_and_owners():
    assert cwe_numbers("CWE-89: SQL Injection") == [89]
    assert cwe_numbers(["CWE-79", "CWE-80"]) == [79, 80]
    assert cwe_numbers(None) == []
    assert category_for_cwes(["CWE-999", "CWE-78"]) == "command_injection"
    assert category_for_cwes("CWE-1") is None
    assert owner_scan("sql_injection") == "data"
    assert owner_scan("hardcoded_secret") == "exposure"
    assert owner_scan("csrf") == "access"
    assert owner_scan("server_side_request_forgery") == "data"
    assert owner_scan("made_up_category") == "data"
    assert is_suppressed(["CWE-400"]) and is_suppressed("CWE-1333")
    assert not is_suppressed(["CWE-400", "CWE-89"]) and not is_suppressed(None)


# ---- gitleaks -----------------------------------------------------------------------


def _gitleaks_report(entries):
    out = []
    for tree, path, rule, line in entries:
        out.append({
            "RuleID": rule, "Description": f"{rule} description", "StartLine": line, "EndLine": line,
            "Match": "REDACTED", "Secret": "REDACTED", "File": f"{tree}/{path}", "Fingerprint": f"{tree}/{path}:{rule}:{line}",
        })
    return out


def _patch_gitleaks(monkeypatch, entries, returncode=0, stderr=""):
    calls = []

    def fake_exec(self, cmd, cwd=None, timeout=None, env=None):
        calls.append({"cmd": list(cmd), "cwd": cwd})
        if "version" in cmd:
            return _completed(stdout="8.30.1\n")
        root = Path(cwd)
        # the staged tree must contain both the added copies and the removed-line files
        calls[-1]["staged"] = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
        report = Path(cmd[cmd.index("--report-path") + 1])
        report.write_text(json.dumps(_gitleaks_report(entries)))
        return _completed(returncode=returncode, stderr=stderr)

    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/gitleaks" if name == "gitleaks" else None)
    monkeypatch.setattr(GitleaksTool, "_exec", fake_exec)
    return calls


def test_gitleaks_reports_added_secret_and_history(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    bundle = build_bundle(SECRETS_DIFF)
    calls = _patch_gitleaks(monkeypatch, [
        ("added", "app/config.py", "aws-access-token", 2),      # on an added line -> reported
        ("added", "app/config.py", "generic-api-key", 4),       # unchanged line -> ignored
        ("removed", "app/config.py", "github-pat", 1),          # removed -> secret in history
        ("added", "docs/setup.md", "generic-api-key", 2),       # docs still count for secrets
    ])
    result = GitleaksTool().run(repo, bundle)
    assert result.status == "completed" and result.version == "8.30.1"
    assert result.candidates == []
    by_cat = {(f["category"], f["file"]): f for f in result.findings}
    assert set(by_cat) == {("hardcoded_secret", "app/config.py"), ("secret_in_history", "app/config.py"), ("hardcoded_secret", "docs/setup.md")}
    added = by_cat[("hardcoded_secret", "app/config.py")]
    assert added["line"] == 2 and added["severity"] == "HIGH" and added["scan"] == "gitleaks" and added["rule_id"] == "aws-access-token"
    assert "REDACTED" not in json.dumps(result.findings) and "AKIA" not in json.dumps(result.findings)
    history = by_cat[("secret_in_history", "app/config.py")]
    assert history["line"] == 2 and history["introduced_by_change"] is False and "rotate" in history["recommendation"].lower()
    scan_call = next(c for c in calls if "dir" in c["cmd"])
    assert "--redact" in scan_call["cmd"] and "--exit-code" in scan_call["cmd"]
    assert "added/app/config.py" in scan_call["staged"] and "removed/app/config.py" in scan_call["staged"]
    assert "added/docs/setup.md" in scan_call["staged"]
    assert not any(s.startswith("removed/docs") for s in scan_call["staged"])   # nothing removed there


def test_gitleaks_moved_secret_not_double_reported(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    bundle = build_bundle(SECRETS_DIFF)
    _patch_gitleaks(monkeypatch, [
        ("added", "app/config.py", "aws-access-token", 2),
        ("removed", "app/config.py", "aws-access-token", 1),
    ])
    result = GitleaksTool().run(repo, bundle)
    assert [f["category"] for f in result.findings] == ["hardcoded_secret"]


def test_gitleaks_honours_repo_ignore_and_config(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    (repo / ".gitleaksignore").write_text("# comment\napp/config.py:aws-access-token:2\n")
    (repo / ".gitleaks.toml").write_text('title = "custom"\n')
    bundle = build_bundle(SECRETS_DIFF)
    calls = _patch_gitleaks(monkeypatch, [])
    GitleaksTool().run(repo, bundle)
    scan_call = next(c for c in calls if "dir" in c["cmd"])
    assert ".gitleaksignore" in scan_call["staged"] and ".gitleaks.toml" in scan_call["staged"]
    assert scan_call["cmd"][scan_call["cmd"].index("--config") + 1].endswith(".gitleaks.toml")


def test_gitleaks_ignore_fingerprints_are_prefixed(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    (repo / ".gitleaksignore").write_text("app/config.py:aws-access-token:2\n")
    captured = {}

    def fake_exec(self, cmd, cwd=None, timeout=None, env=None):
        if "version" in cmd:
            return _completed(stdout="8.30.1")
        captured["ignore"] = (Path(cwd) / ".gitleaksignore").read_text()
        Path(cmd[cmd.index("--report-path") + 1]).write_text("[]")
        return _completed()

    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/gitleaks")
    monkeypatch.setattr(GitleaksTool, "_exec", fake_exec)
    GitleaksTool().run(repo, build_bundle(SECRETS_DIFF))
    assert "added/app/config.py:aws-access-token:2" in captured["ignore"]


def test_gitleaks_failure_surfaces(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    _patch_gitleaks(monkeypatch, [], returncode=126, stderr="bad config")
    result = GitleaksTool().run(repo, build_bundle(SECRETS_DIFF))
    assert result.status == "failed" and "bad config" in result.error


def test_gitleaks_nothing_to_scan(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/gitleaks")
    monkeypatch.setattr(GitleaksTool, "_exec", lambda self, cmd, **kw: _completed(stdout="8.30.1"))
    deleted_only = "diff --git a/gone.py b/gone.py\ndeleted file mode 100644\n--- a/gone.py\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-x = 1\n"
    result = GitleaksTool().run(tmp_path, build_bundle(deleted_only))
    # a deleted file still has removed lines, so it is staged and scanned
    assert result.status in ("completed", "failed")


# ---- semgrep ------------------------------------------------------------------------


def _semgrep_result(path, line, check_id, cwe, confidence="LOW", severity="WARNING", subcategory=("audit",), category="security", end=None, **extra_meta):
    meta = {"cwe": cwe, "confidence": confidence, "category": category, "subcategory": list(subcategory), "references": ["https://example.com/rule"]}
    meta.update(extra_meta)
    return {
        "check_id": check_id, "path": path,
        "start": {"line": line, "col": 1}, "end": {"line": end or line, "col": 10},
        "extra": {"message": f"Message for {check_id}.", "severity": severity, "metadata": meta, "lines": "requires login"},
    }


def _patch_semgrep(monkeypatch, results, errors=None, returncode=0, stdout=None, binary="semgrep"):
    calls = []

    def fake_exec(self, cmd, cwd=None, timeout=None, env=None):
        calls.append(list(cmd))
        if "--version" in cmd:
            return _completed(stdout="1.176.1\n")
        payload = stdout if stdout is not None else json.dumps({"version": "1.176.1", "results": results, "errors": errors or []})
        return _completed(stdout=payload, returncode=returncode)

    monkeypatch.setattr("shutil.which", lambda name: f"/usr/local/bin/{name}" if name == binary else None)
    monkeypatch.setattr(SemgrepTool, "_exec", fake_exec)
    return calls


def test_semgrep_candidates_filtered_mapped_and_snippeted(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    bundle = build_bundle(SECRETS_DIFF)
    calls = _patch_semgrep(monkeypatch, [
        _semgrep_result("app/config.py", 2, "generic.secrets.aws-key", ["CWE-798: Use of Hard-coded Credentials"], severity="ERROR"),
        _semgrep_result("app/config.py", 3, "python.lang.sql", "CWE-89: SQL Injection", confidence="HIGH", subcategory=("vuln",)),   # unchanged line
        _semgrep_result("app/config.py", 2, "python.lang.redos", "CWE-1333: ReDoS"),                                                  # suppressed class
        _semgrep_result("app/config.py", 2, "python.best-practice.x", None, category="best-practice"),                                # not security
        _semgrep_result("app/config.py", 2, "python.lang.mystery", None),                                                             # security, no CWE
        _semgrep_result("app/config.py", 2, "python.lang.timeout", "CWE-400: Resource Exhaustion"),
    ])
    result = SemgrepTool(config="p/security-audit").run(repo, bundle)
    assert result.status == "completed" and result.version == "1.176.1"
    assert result.findings == []
    ids = [c["id"] for c in result.candidates]
    assert ids == ["semgrep-1", "semgrep-2"]
    secret, mystery = result.candidates
    assert secret["category"] == "hardcoded_secret" and secret["owner_scan"] == "exposure" and secret["severity"] == "HIGH"
    assert secret["snippet"] == ""                       # never echo a secret
    assert secret["confidence"] == 0.45                  # LOW confidence, audit subcategory
    assert secret["cwe"] == ["CWE-798: Use of Hard-coded Credentials"]
    assert mystery["category"] == "security_issue" and mystery["owner_scan"] == "data"
    assert mystery["snippet"] == 'AWS_KEY = "AKIAQ4T5RXKR2AB7ZZZZ"'
    assert "3 non-security or out-of-scope" in result.notes and "1 hit(s) on unchanged lines" in result.notes
    scan_cmd = next(c for c in calls if "scan" in c)
    assert "--metrics=off" in scan_cmd and "p/security-audit" in scan_cmd and scan_cmd[-2:] == ["app/config.py", "docs/setup.md"]


def test_category_title():
    assert category_title("sql_injection") == "SQL injection"
    assert category_title("xss_dom") == "XSS DOM"
    assert category_title("path_traversal") == "Path traversal"
    assert category_title("security_issue") == "Security issue"


def test_semgrep_confidence_from_metadata(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    bundle = build_bundle(SECRETS_DIFF)
    _patch_semgrep(monkeypatch, [
        _semgrep_result("app/config.py", 2, "r.high", "CWE-89", confidence="HIGH", subcategory=("vuln",)),
        _semgrep_result("app/config.py", 2, "r.medium", "CWE-78", confidence="MEDIUM", subcategory=()),
        _semgrep_result("app/config.py", 2, "r.none", "CWE-22", confidence=None, subcategory=()),
    ])
    result = SemgrepTool().run(repo, bundle)
    by_rule = {c["rule_id"]: c["confidence"] for c in result.candidates}
    assert by_rule == {"r.high": 0.85, "r.medium": 0.65, "r.none": 0.55}
    assert [c["rule_id"] for c in result.candidates] == ["r.high", "r.medium", "r.none"]   # sorted by confidence


def test_semgrep_uses_opengrep_when_present(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    calls = _patch_semgrep(monkeypatch, [], binary="opengrep")
    result = SemgrepTool().run(repo, build_bundle(SECRETS_DIFF))
    assert result.status == "completed"
    assert calls[0][0].endswith("opengrep")


def test_semgrep_errors(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    bundle = build_bundle(SECRETS_DIFF)
    _patch_semgrep(monkeypatch, [], stdout="not json", returncode=2)
    assert "unparseable" in SemgrepTool().run(repo, bundle).error
    _patch_semgrep(monkeypatch, [], stdout="", returncode=2)
    assert "no output" in SemgrepTool().run(repo, bundle).error
    _patch_semgrep(monkeypatch, [], errors=[{"message": "could not fetch ruleset"}], returncode=7)
    assert "could not fetch ruleset" in SemgrepTool().run(repo, bundle).error
    # errors alongside results are only noted
    _patch_semgrep(monkeypatch, [_semgrep_result("app/config.py", 2, "r", "CWE-89")], errors=[{"message": "partial parse"}], returncode=0)
    result = SemgrepTool().run(repo, bundle)
    assert result.status == "completed" and "partial parse" in result.notes


def test_semgrep_nothing_present(tmp_path, monkeypatch):
    _patch_semgrep(monkeypatch, [])
    result = SemgrepTool().run(tmp_path, build_bundle(SECRETS_DIFF))   # files not in checkout
    assert result.status == "completed" and result.candidates == [] and "no touched files" in result.notes


# ---- registry -----------------------------------------------------------------------


def test_run_tools_registry_and_parallel(tmp_path, monkeypatch):
    with pytest.raises(ValueError):
        get_tool("snyk")
    assert isinstance(get_tool("semgrep", options={"semgrep_config": "p/x"}), SemgrepTool)
    assert get_tool("semgrep", options={"semgrep_config": "p/x"}).config == "p/x"
    assert get_tool("gitleaks", options={"gitleaks_config": "/c.toml"}).config_path == "/c.toml"
    monkeypatch.setattr("shutil.which", lambda name: None)
    results = run_tools(["semgrep", "gitleaks"], tmp_path, build_bundle(SECRETS_DIFF))
    assert [r.tool for r in results] == ["semgrep", "gitleaks"]
    assert all(r.status == "skipped" for r in results)
    assert run_tools([], tmp_path, build_bundle(SECRETS_DIFF)) == []
    assert run_tools(["gitleaks"], tmp_path, build_bundle("")) == []
    assert ToolResult(tool="x", status="completed").to_dict()["findings_count"] == 0

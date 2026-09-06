import json
import subprocess

from ai_security_review.constants import BACKEND_CLAUDE_CODE
from ai_security_review.scan_runner import ScanRunner


def test_claude_code_backend_parses_wrapper(tmp_path, bundle, helpers, monkeypatch):
    inner = helpers["scan_payload"]([helpers["finding"]()])
    wrapper = {"type": "result", "subtype": "success", "is_error": False, "result": "Here you go:\n" + json.dumps(inner)}
    calls = {}

    def fake_run(cmd, **kw):
        calls["cmd"] = cmd
        calls["input"] = kw["input"]
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(wrapper), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("ai_security_review.scan_runner.shutil.which", lambda _: "/usr/bin/claude")
    runner = ScanRunner(tmp_path, backend=BACKEND_CLAUDE_CODE, model="claude-opus-5")
    result = runner.run_one("data", bundle, helpers["triage_payload"]())
    assert result.status == "completed"
    assert result.findings[0]["scan"] == "data"
    assert "-p" in calls["cmd"] and "--append-system-prompt" in calls["cmd"]
    assert "REQUIRED OUTPUT" in calls["input"]
    assert "Write" in calls["cmd"][calls["cmd"].index("--disallowedTools") + 1]


def test_claude_code_backend_missing_cli(tmp_path, bundle, helpers, monkeypatch):
    monkeypatch.setattr("ai_security_review.scan_runner.shutil.which", lambda _: None)
    result = ScanRunner(tmp_path, backend=BACKEND_CLAUDE_CODE).run_one("access", bundle, helpers["triage_payload"]())
    assert result.status == "failed" and "not found" in result.error


def test_claude_code_backend_retries_then_fails(tmp_path, bundle, helpers, monkeypatch):
    attempts = []

    def fake_run(cmd, **kw):
        attempts.append(1)
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("ai_security_review.scan_runner.shutil.which", lambda _: "/usr/bin/claude")
    monkeypatch.setattr("ai_security_review.scan_runner.time.sleep", lambda _: None)
    result = ScanRunner(tmp_path, backend=BACKEND_CLAUDE_CODE).run_one("exposure", bundle, helpers["triage_payload"]())
    assert result.status == "failed" and len(attempts) == 2


def test_run_all_parallel_preserves_order(tmp_path, bundle, helpers, fake_client_factory):
    client = fake_client_factory({"scan": helpers["scan_payload"]([])})
    runner = ScanRunner(tmp_path, client=client, include_context_files=False)
    results = runner.run_all(["access", "data"], bundle, helpers["triage_payload"]())
    assert [r.scan for r in results] == ["access", "data"]
    assert all(r.status == "completed" for r in results)

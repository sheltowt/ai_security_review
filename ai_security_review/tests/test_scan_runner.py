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


def _cc_runner(tmp_path, monkeypatch, outcomes):
    """Claude Code runner whose subprocess.run yields each outcome in turn (exception or CompletedProcess)."""
    outcomes = list(outcomes)
    calls = []

    def fake_run(cmd, **kw):
        calls.append(kw)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("ai_security_review.scan_runner.shutil.which", lambda _: "/usr/bin/claude")
    monkeypatch.setattr("ai_security_review.scan_runner.time.sleep", lambda _: None)
    return ScanRunner(tmp_path, backend=BACKEND_CLAUDE_CODE, claude_code_timeout=7), calls


def _ok(stdout):
    return subprocess.CompletedProcess([], 0, stdout=stdout, stderr="")


def test_claude_code_timeout(tmp_path, bundle, helpers, monkeypatch):
    runner, _ = _cc_runner(tmp_path, monkeypatch, [subprocess.TimeoutExpired("claude", 7)])
    r = runner.run_one("data", bundle, helpers["triage_payload"]())
    assert r.status == "failed" and "timed out after 7s" in r.error


def test_claude_code_prompt_too_long_aborts_without_retry(tmp_path, bundle, helpers, monkeypatch):
    wrapper = {"type": "result", "is_error": True, "result": "Prompt is too long"}
    runner, calls = _cc_runner(tmp_path, monkeypatch, [_ok(json.dumps(wrapper))])
    r = runner.run_one("data", bundle, helpers["triage_payload"]())
    assert r.status == "failed" and "too long" in r.error.lower()
    assert len(calls) == 1


def test_claude_code_is_error_then_success(tmp_path, bundle, helpers, monkeypatch):
    bad = {"type": "result", "is_error": True, "result": "error_during_execution"}
    good = {"type": "result", "is_error": False, "result": json.dumps(helpers["scan_payload"]([]))}
    runner, calls = _cc_runner(tmp_path, monkeypatch, [_ok(json.dumps(bad)), _ok(json.dumps(good))])
    r = runner.run_one("exposure", bundle, helpers["triage_payload"]())
    assert r.status == "completed" and len(calls) == 2


def test_claude_code_unparseable_and_missing_findings(tmp_path, bundle, helpers, monkeypatch):
    no_findings = {"type": "result", "is_error": False, "result": '{"notes": "forgot the findings key"}'}
    runner, calls = _cc_runner(tmp_path, monkeypatch, [_ok("garbage <<<"), _ok(json.dumps(no_findings))])
    r = runner.run_one("access", bundle, helpers["triage_payload"]())
    assert r.status == "failed" and "findings object" in r.error
    assert len(calls) == 2


def test_claude_code_passes_cwd_and_timeout(tmp_path, bundle, helpers, monkeypatch):
    good = {"type": "result", "is_error": False, "result": json.dumps(helpers["scan_payload"]([]))}
    runner, calls = _cc_runner(tmp_path, monkeypatch, [_ok(json.dumps(good))])
    runner.run_one("data", bundle, helpers["triage_payload"]())
    assert calls[0]["cwd"] == tmp_path and calls[0]["timeout"] == 7


def test_api_backend_without_client_fails_cleanly(tmp_path, bundle, helpers):
    r = ScanRunner(tmp_path, client=None, include_context_files=False).run_one("data", bundle, helpers["triage_payload"]())
    assert r.status == "failed" and "requires a ClaudeClient" in r.error


def test_run_all_survives_crash_in_worker(tmp_path, bundle, helpers, monkeypatch):
    runner = ScanRunner(tmp_path, include_context_files=False)

    def boom(*a, **k):
        raise RuntimeError("worker crashed")

    monkeypatch.setattr(runner, "run_one", boom)
    results = runner.run_all(["data"], bundle, helpers["triage_payload"]())
    assert results[0].status == "failed" and "worker crashed" in results[0].error


def test_run_all_empty(tmp_path, bundle, helpers):
    assert ScanRunner(tmp_path).run_all([], bundle, helpers["triage_payload"]()) == []


def test_unknown_scan_key_is_failed_result(tmp_path, bundle, helpers):
    r = ScanRunner(tmp_path, include_context_files=False).run_one("network", bundle, helpers["triage_payload"]())
    assert r.status == "failed" and "Unknown scan" in r.error

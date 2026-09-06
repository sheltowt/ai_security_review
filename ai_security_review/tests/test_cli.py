import json
import os
from pathlib import Path

import pytest

from ai_security_review import cli
from ai_security_review.constants import EXIT_CONFIGURATION_ERROR, EXIT_FINDINGS, EXIT_SUCCESS


@pytest.fixture
def patched_pipeline(monkeypatch, helpers):
    captured = {}

    def fake_run_pipeline(config, bundle, pr_context, client=None):
        captured["config"] = config
        captured["bundle"] = bundle
        from ai_security_review.findings import normalize_finding

        findings = [normalize_finding({**helpers["finding"](), "scan": "data"})] if captured.get("with_findings", True) else []
        return {
            "triage": {**helpers["triage_payload"](), "selected_scans": ["data"], "skipped": False},
            "scan_results": [{"scan": "data", "status": "completed", "error": None}],
            "findings": findings,
            "severity_counts": {"HIGH": len(findings), "MEDIUM": 0, "LOW": 0},
            "filter_summary": {"total": len(findings), "kept": len(findings)},
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "error": None,
        }

    monkeypatch.setattr(cli, "run_pipeline", fake_run_pipeline)
    return captured


def test_cli_diff_file_fails_on_high(tmp_path, sample_diff, patched_pipeline, capsys):
    diff_path = tmp_path / "change.diff"
    diff_path.write_text(sample_diff)
    out = tmp_path / "results.json"
    code = cli.main(["--diff-file", str(diff_path), "--output", str(out), "--repo-dir", str(tmp_path), "--exclude-dirs", "vendor"])
    assert code == EXIT_FINDINGS
    data = json.loads(out.read_text())
    assert data["findings"][0]["category"] == "sql_injection"
    assert "AI Security Review" in capsys.readouterr().out
    assert patched_pipeline["config"].exclude_dirs == ["vendor"]
    assert "vendor/lib.js" in patched_pipeline["bundle"].excluded


def test_cli_fail_on_none(tmp_path, sample_diff, patched_pipeline):
    diff_path = tmp_path / "change.diff"
    diff_path.write_text(sample_diff)
    code = cli.main(["--diff-file", str(diff_path), "--output", str(tmp_path / "r.json"), "--fail-on", "NONE"])
    assert code == EXIT_SUCCESS


def test_cli_forced_scans_and_instructions(tmp_path, sample_diff, patched_pipeline):
    (tmp_path / "change.diff").write_text(sample_diff)
    instr = tmp_path / "instr"
    instr.mkdir()
    (instr / "access.md").write_text("Tenants are keyed by org_id.")
    (tmp_path / "triage.txt").write_text("Billing code is critical.")
    cli.main([
        "--diff-file", str(tmp_path / "change.diff"), "--output", str(tmp_path / "r.json"),
        "--scans", "access,data", "--scan-instructions-dir", str(instr), "--triage-instructions", str(tmp_path / "triage.txt"),
        "--backend", "claude-code", "--fail-on", "none",
    ])
    cfg = patched_pipeline["config"]
    assert cfg.forced_scans == ["access", "data"]
    assert cfg.custom_scan_instructions == {"access": "Tenants are keyed by org_id."}
    assert cfg.custom_triage_instructions == "Billing code is critical."
    assert cfg.backend == "claude-code"


def test_cli_bad_scan_name(tmp_path, sample_diff):
    with pytest.raises(SystemExit):
        cli.main(["--diff-file", "x", "--scans", "network"])


def test_cli_missing_diff_file(tmp_path):
    code = cli.main(["--diff-file", str(tmp_path / "nope.diff"), "--output", str(tmp_path / "r.json")])
    assert code == EXIT_CONFIGURATION_ERROR
    assert "error" in json.loads((tmp_path / "r.json").read_text())


def test_cli_github_outputs(tmp_path, sample_diff, patched_pipeline, monkeypatch):
    (tmp_path / "change.diff").write_text(sample_diff)
    gh_out = tmp_path / "gh_output"
    step = tmp_path / "step_summary.md"
    monkeypatch.setenv("GITHUB_OUTPUT", str(gh_out))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step))
    cli.main(["--diff-file", str(tmp_path / "change.diff"), "--output", str(tmp_path / "r.json"), "--fail-on", "none"])
    text = gh_out.read_text()
    assert "findings-count=1" in text and "risk-level=high" in text and "selected-scans=data" in text
    assert "AI Security Review" in step.read_text()

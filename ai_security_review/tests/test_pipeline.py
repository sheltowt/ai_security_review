import json
from pathlib import Path

from ai_security_review.constants import BACKEND_API
from ai_security_review.diff import build_bundle
from ai_security_review.pipeline import PipelineConfig, run_pipeline
from ai_security_review.report import render_markdown_summary


def _config(tmp_path, **kw):
    return PipelineConfig(repo_dir=tmp_path, backend=BACKEND_API, include_context_files=False, **kw)


def test_pipeline_runs_only_selected_scans(tmp_path, bundle, fake_client_factory, helpers):
    client = fake_client_factory(
        {
            "triage": helpers["triage_payload"](),
            "scan:data": helpers["scan_payload"]([helpers["finding"]()]),
            "scan:exposure": helpers["scan_payload"]([helpers["finding"](line=16, category="secret_in_logs", title="Authorization header logged", description="Bearer token in logs", severity="MEDIUM", confidence=0.85)]),
            "scan:access": helpers["scan_payload"]([helpers["finding"](category="idor")]),
        }
    )
    result = run_pipeline(_config(tmp_path), bundle, {"repo": "o/r", "number": 1, "title": "t"}, client=client)
    labels = [c["label"] for c in client.calls]
    assert labels[0] == "triage"
    assert sorted(labels[1:]) == ["scan:data", "scan:exposure"]      # access skipped by triage
    assert [s["scan"] for s in result["scan_results"]] == ["data", "exposure"]
    assert [f["category"] for f in result["findings"]] == ["sql_injection", "secret_in_logs"]
    assert result["severity_counts"] == {"HIGH": 1, "MEDIUM": 1, "LOW": 0}
    assert result["usage"]["input_tokens"] == 300
    assert result["error"] is None
    json.dumps(result)  # serialisable


def test_pipeline_forced_scans_skip_triage(tmp_path, bundle, fake_client_factory, helpers):
    client = fake_client_factory({"scan": helpers["scan_payload"]([])})
    result = run_pipeline(_config(tmp_path, forced_scans=["access"]), bundle, client=client)
    assert [c["label"] for c in client.calls] == ["scan:access"]
    assert result["triage"]["skipped"] is True
    assert result["findings"] == []


def test_pipeline_always_scans(tmp_path, bundle, fake_client_factory, helpers):
    client = fake_client_factory({"triage": helpers["triage_payload"](data=False, exposure=False, access=False), "scan": helpers["scan_payload"]([])})
    result = run_pipeline(_config(tmp_path, always_scans=["exposure"]), bundle, client=client)
    assert result["triage"]["selected_scans"] == ["exposure"]
    assert "(always-run)" in result["triage"]["scans"]["exposure"]["reason"]


def test_pipeline_triage_failure(tmp_path, bundle, fake_client_factory):
    client = fake_client_factory({}, fail_labels=["triage"])
    result = run_pipeline(_config(tmp_path), bundle, client=client)
    assert result["error"].startswith("Triage failed")
    assert result["scan_results"] == []


def test_pipeline_partial_scan_failure(tmp_path, bundle, fake_client_factory, helpers):
    client = fake_client_factory({"triage": helpers["triage_payload"](), "scan:data": helpers["scan_payload"]([helpers["finding"]()])}, fail_labels=["scan:exposure"])
    result = run_pipeline(_config(tmp_path), bundle, client=client)
    statuses = {s["scan"]: s["status"] for s in result["scan_results"]}
    assert statuses == {"data": "completed", "exposure": "failed"}
    assert result["error"] is None            # partial results still count
    assert len(result["findings"]) == 1


def test_pipeline_all_scans_fail(tmp_path, bundle, fake_client_factory, helpers):
    client = fake_client_factory({"triage": helpers["triage_payload"]()}, fail_labels=["scan:data", "scan:exposure"])
    result = run_pipeline(_config(tmp_path), bundle, client=client)
    assert result["error"].startswith("All selected scans failed")


def test_pipeline_empty_diff(tmp_path, fake_client_factory):
    client = fake_client_factory({})
    result = run_pipeline(_config(tmp_path), build_bundle(""), client=client)
    assert client.calls == []
    assert result["findings"] == []


def test_context_files_attached(tmp_path, sample_diff, fake_client_factory, helpers):
    (tmp_path / "app" / "api").mkdir(parents=True)
    (tmp_path / "app" / "api" / "users.py").write_text("FULL CONTENTS OF USERS")
    bundle = build_bundle(sample_diff)
    client = fake_client_factory({"triage": helpers["triage_payload"](exposure=False), "scan": helpers["scan_payload"]([])})
    run_pipeline(PipelineConfig(repo_dir=tmp_path, backend=BACKEND_API), bundle, client=client)
    scan_call = next(c for c in client.calls if c["label"] == "scan:data")
    assert "FULL CONTENTS OF USERS" in scan_call["user"]


def test_markdown_summary(tmp_path, bundle, fake_client_factory, helpers):
    client = fake_client_factory({"triage": helpers["triage_payload"](), "scan": helpers["scan_payload"]([helpers["finding"]()])})
    result = run_pipeline(_config(tmp_path), bundle, client=client)
    md = render_markdown_summary(result)
    assert "## 🛡️ AI Security Review" in md
    assert "| Data handling | ✅ ran" in md
    assert "| Access control | — skipped" in md
    assert "SQL injection in export_user" in md
    assert "app/api/users.py:15" in md

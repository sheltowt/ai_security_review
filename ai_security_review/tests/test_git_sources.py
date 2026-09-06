"""Diff acquisition from real git repositories and context-file collection."""

import subprocess
from pathlib import Path

import pytest

from ai_security_review import cli
from ai_security_review.constants import EXIT_CONFIGURATION_ERROR, EXIT_SUCCESS
from ai_security_review.diff import build_bundle, collect_context_files, git_diff, git_working_tree_diff


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repo with main (one commit) and a feature branch that adds a file and edits another."""
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "app.py").write_text("def handler(x):\n    return x\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "base")
    _git(tmp_path, "checkout", "-q", "-b", "feature")
    (tmp_path / "app.py").write_text("import os\n\ndef handler(x):\n    return os.system(x)\n")
    (tmp_path / "new.py").write_text("SECRET = 'abc'\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "feature")
    return tmp_path


def test_git_diff_merge_base(repo):
    text = git_diff(repo, "main", "HEAD")
    b = build_bundle(text)
    assert sorted(b.paths) == ["app.py", "new.py"]
    assert next(f for f in b.files if f.path == "new.py").status == "added"
    assert "os.system(x)" in text


def test_git_diff_two_dot(repo):
    assert "os.system" in git_diff(repo, "main", "HEAD", merge_base=False)


def test_git_diff_bad_ref(repo):
    with pytest.raises(RuntimeError, match="git diff failed"):
        git_diff(repo, "does-not-exist")


def test_working_tree_diff(repo):
    (repo / "app.py").write_text("import os\n\ndef handler(x):\n    return os.system(x)  # edited\n")
    assert "# edited" in git_working_tree_diff(repo)
    assert "# edited" not in git_diff(repo, "main")           # committed range does not see it
    against_main = git_working_tree_diff(repo, "main")
    assert "# edited" in against_main and "SECRET" in against_main


def test_cli_base_range(repo, monkeypatch):
    captured = {}

    def fake_pipeline(config, bundle, pr_context, client=None):
        captured["paths"] = bundle.paths
        return {"triage": {"selected_scans": [], "scans": {}, "skipped": True}, "scan_results": [], "findings": [], "severity_counts": {}, "filter_summary": {}, "usage": {}, "error": None}

    monkeypatch.setattr(cli, "run_pipeline", fake_pipeline)
    code = cli.main(["--base", "main", "--repo-dir", str(repo), "--output", str(repo / "r.json"), "--fail-on", "none"])
    assert code == EXIT_SUCCESS
    assert sorted(captured["paths"]) == ["app.py", "new.py"]


def test_cli_working_tree_default(repo, monkeypatch):
    (repo / "app.py").write_text("changed\n")
    captured = {}

    def fake_pipeline(config, bundle, pr_context, client=None):
        captured["paths"] = bundle.paths
        return {"triage": {"selected_scans": [], "scans": {}, "skipped": True}, "scan_results": [], "findings": [], "severity_counts": {}, "filter_summary": {}, "usage": {}, "error": None}

    monkeypatch.setattr(cli, "run_pipeline", fake_pipeline)
    cli.main(["--repo-dir", str(repo), "--output", str(repo / "r.json"), "--fail-on", "none"])
    assert captured["paths"] == ["app.py"]


def test_cli_stdin_diff(sample_diff, tmp_path, monkeypatch):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(sample_diff))
    captured = {}

    def fake_pipeline(config, bundle, pr_context, client=None):
        captured["n"] = len(bundle.files)
        return {"triage": {"selected_scans": [], "scans": {}, "skipped": True}, "scan_results": [], "findings": [], "severity_counts": {}, "filter_summary": {}, "usage": {}, "error": None}

    monkeypatch.setattr(cli, "run_pipeline", fake_pipeline)
    cli.main(["--diff-file", "-", "--output", str(tmp_path / "r.json"), "--fail-on", "none"])
    assert captured["n"] == 3


def test_cli_bad_git_ref_is_config_error(repo):
    code = cli.main(["--base", "nope", "--repo-dir", str(repo), "--output", str(repo / "r.json")])
    assert code == EXIT_CONFIGURATION_ERROR


def test_cli_pr_source_and_comment(tmp_path, sample_diff, monkeypatch):
    """--repo/--pr fetches from GitHub; --comment-pr posts summary and inline findings."""
    from ai_security_review.findings import normalize_finding

    class FakeGH:
        instances = []

        def __init__(self):
            self.posted = []
            FakeGH.instances.append(self)

        def get_pr(self, repo, number):
            return {"repo": repo, "number": number, "title": "t", "body": "", "author": "a", "head_sha": "sha", "base_ref": "main", "head_ref": "f"}

        def get_pr_diff(self, repo, number):
            return sample_diff

        def post_summary_comment(self, repo, number, body):
            self.posted.append(("summary", body))

        def post_inline_review(self, repo, number, sha, comments):
            self.posted.append(("inline", sha, comments))
            return len(comments)

    monkeypatch.setattr("ai_security_review.github_client.GitHubClient", FakeGH)
    finding = normalize_finding({"file": "app/api/users.py", "line": 15, "severity": "HIGH", "category": "sql_injection", "confidence": 0.9, "scan": "data"})

    def fake_pipeline(config, bundle, pr_context, client=None):
        assert pr_context["number"] == 7
        return {"triage": {"selected_scans": ["data"], "scans": {}, "skipped": False, "summary": "s", "risk_level": "high"}, "scan_results": [], "findings": [finding], "severity_counts": {"HIGH": 1}, "filter_summary": {}, "usage": {}, "error": None}

    monkeypatch.setattr(cli, "run_pipeline", fake_pipeline)
    code = cli.main(["--repo", "o/r", "--pr", "7", "--comment-pr", "--output", str(tmp_path / "r.json"), "--fail-on", "none"])
    assert code == EXIT_SUCCESS
    posted = FakeGH.instances[-1].posted
    assert posted[0][0] == "summary" and "AI Security Review" in posted[0][1]
    assert posted[1][0] == "inline" and posted[1][1] == "sha"
    assert posted[1][2][0]["path"] == "app/api/users.py" and posted[1][2][0]["line"] == 15


def test_cli_comment_failure_does_not_crash(tmp_path, sample_diff, monkeypatch):
    class BrokenGH:
        def __init__(self):
            raise RuntimeError("no token")

    monkeypatch.setattr("ai_security_review.github_client.GitHubClient", BrokenGH)
    (tmp_path / "c.diff").write_text(sample_diff)

    def fake_pipeline(config, bundle, pr_context, client=None):
        return {"triage": {"selected_scans": [], "scans": {}, "skipped": True}, "scan_results": [], "findings": [], "severity_counts": {}, "filter_summary": {}, "usage": {}, "error": None}

    monkeypatch.setattr(cli, "run_pipeline", fake_pipeline)
    # --comment-pr without PR context only warns
    assert cli.main(["--diff-file", str(tmp_path / "c.diff"), "--comment-pr", "--output", str(tmp_path / "r.json"), "--fail-on", "none"]) == EXIT_SUCCESS
    # and a failing client during a PR run is logged, not raised
    cli._comment_on_pr({"repo": "o/r", "number": 1, "head_sha": "s"}, {"findings": []}, "md")


def test_cli_runtime_error_when_review_failed(tmp_path, sample_diff, monkeypatch):
    (tmp_path / "c.diff").write_text(sample_diff)
    monkeypatch.setattr(cli, "run_pipeline", lambda *a, **k: {"triage": None, "scan_results": [], "findings": [], "severity_counts": {}, "filter_summary": {}, "usage": {}, "error": "Triage failed: boom"})
    assert cli.main(["--diff-file", str(tmp_path / "c.diff"), "--output", str(tmp_path / "r.json")]) == 3


def test_cli_pipeline_crash_writes_error(tmp_path, sample_diff, monkeypatch):
    (tmp_path / "c.diff").write_text(sample_diff)

    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cli, "run_pipeline", boom)
    assert cli.main(["--diff-file", str(tmp_path / "c.diff"), "--output", str(tmp_path / "r.json")]) == 3
    assert "kaboom" in (tmp_path / "r.json").read_text()


# ---- context files ---------------------------------------------------------------------


def test_collect_context_files_skips_deleted_binary_and_missing(tmp_path):
    diff = (
        "diff --git a/keep.py b/keep.py\n--- a/keep.py\n+++ b/keep.py\n@@ -1 +1 @@\n-a\n+b\n"
        "diff --git a/gone.py b/gone.py\ndeleted file mode 100644\n--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
        "diff --git a/img.bin b/img.bin\n--- a/img.bin\n+++ b/img.bin\n@@ -1 +1 @@\n-x\n+y\n"
        "diff --git a/missing.py b/missing.py\n--- a/missing.py\n+++ b/missing.py\n@@ -1 +1 @@\n-x\n+y\n"
    )
    (tmp_path / "keep.py").write_text("print('hi')\n")
    (tmp_path / "gone.py").write_text("should not be read\n")
    (tmp_path / "img.bin").write_bytes(b"\x89PNG\x00\x00binary")
    ctx = collect_context_files(tmp_path, build_bundle(diff))
    assert ctx == {"keep.py": "print('hi')\n"}


def test_collect_context_files_size_caps(tmp_path, monkeypatch):
    monkeypatch.setattr("ai_security_review.diff.MAX_CONTEXT_FILE_CHARS", 50)
    monkeypatch.setattr("ai_security_review.diff.MAX_CONTEXT_TOTAL_CHARS", 120)
    diff = "".join(
        f"diff --git a/f{i}.py b/f{i}.py\n--- a/f{i}.py\n+++ b/f{i}.py\n@@ -1 +1 @@\n-a\n+b\n" for i in range(4)
    )
    for i in range(4):
        (tmp_path / f"f{i}.py").write_text("x" * 200)
    ctx = collect_context_files(tmp_path, build_bundle(diff))
    assert all("[file truncated for size]" in v for v in ctx.values())
    assert all(v.startswith("x" * 50) for v in ctx.values())
    assert len(ctx) < 4                                    # total cap stopped collection

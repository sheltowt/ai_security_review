"""GitHub client tests against a fake requests.Session."""

import json
from typing import Any, Dict, List, Optional

import pytest

from ai_security_review.github_client import COMMENT_MARKER, INLINE_MARKER, GitHubClient


class _Resp:
    def __init__(self, status: int, payload: Any = None, text: Optional[str] = None):
        self.status_code = status
        self.ok = 200 <= status < 300
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if not self.ok:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Routes (method, path) to canned responses and records every call."""

    def __init__(self):
        self.headers: Dict[str, str] = {}
        self.routes: Dict[tuple, Any] = {}
        self.calls: List[Dict[str, Any]] = []

    def route(self, method: str, path: str, response):
        self.routes[(method, path)] = response

    def _do(self, method, url, **kw):
        path = url.split("https://api.github.com", 1)[1]
        self.calls.append({"method": method, "path": path, **kw})
        handler = self.routes.get((method, path))
        if handler is None:
            raise AssertionError(f"unexpected {method} {path}")
        return handler(kw) if callable(handler) else handler

    def get(self, url, **kw):
        return self._do("GET", url, **kw)

    def post(self, url, **kw):
        return self._do("POST", url, **kw)

    def patch(self, url, **kw):
        return self._do("PATCH", url, **kw)


@pytest.fixture
def gh():
    client = GitHubClient(token="t0k")
    client.session = FakeSession()
    return client


def test_requires_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(ValueError):
        GitHubClient()


def test_token_and_api_url_from_env(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "env-token")
    monkeypatch.setenv("GITHUB_API_URL", "https://ghe.example.com/api/v3/")
    c = GitHubClient()
    assert c.api_url == "https://ghe.example.com/api/v3"
    assert c.session.headers["Authorization"] == "Bearer env-token"


def test_get_pr_shapes_context(gh):
    gh.session.route("GET", "/repos/o/r/pulls/5", _Resp(200, {
        "number": 5, "title": "Add export", "body": None, "user": {"login": "dev"},
        "head": {"sha": "abc123", "ref": "feature"}, "base": {"ref": "main"},
    }))
    ctx = gh.get_pr("o/r", 5)
    assert ctx == {"repo": "o/r", "number": 5, "title": "Add export", "body": "", "author": "dev", "head_sha": "abc123", "base_ref": "main", "head_ref": "feature"}


def test_get_pr_diff_uses_diff_accept_header(gh):
    gh.session.route("GET", "/repos/o/r/pulls/5", lambda kw: _Resp(200, text="diff --git a/x b/x\n") if kw["headers"]["Accept"] == "application/vnd.github.diff" else _Resp(500, {}))
    assert gh.get_pr_diff("o/r", 5).startswith("diff --git")


def test_get_pr_raises_on_error(gh):
    gh.session.route("GET", "/repos/o/r/pulls/5", _Resp(404, {"message": "not found"}))
    with pytest.raises(RuntimeError):
        gh.get_pr("o/r", 5)


def test_summary_comment_created_when_absent(gh):
    gh.session.route("GET", "/repos/o/r/issues/5/comments", _Resp(200, [{"id": 1, "body": "unrelated"}]))
    gh.session.route("POST", "/repos/o/r/issues/5/comments", _Resp(201, {"id": 2}))
    gh.post_summary_comment("o/r", 5, "## Summary")
    post = [c for c in gh.session.calls if c["method"] == "POST"][0]
    assert post["json"]["body"].startswith(COMMENT_MARKER)
    assert "## Summary" in post["json"]["body"]


def test_summary_comment_updated_in_place(gh):
    gh.session.route("GET", "/repos/o/r/issues/5/comments", _Resp(200, [{"id": 9, "body": f"{COMMENT_MARKER}\nold"}]))
    gh.session.route("PATCH", "/repos/o/r/issues/comments/9", _Resp(200, {"id": 9}))
    gh.post_summary_comment("o/r", 5, "new")
    methods = [c["method"] for c in gh.session.calls]
    assert methods == ["GET", "PATCH"]


def test_has_existing_summary(gh):
    gh.session.route("GET", "/repos/o/r/issues/5/comments", _Resp(200, [{"body": f"x {COMMENT_MARKER}"}]))
    assert gh.has_existing_summary("o/r", 5)
    gh.session.route("GET", "/repos/o/r/issues/5/comments", _Resp(200, []))
    assert not gh.has_existing_summary("o/r", 5)


def test_inline_review_posts_only_new_findings(gh):
    gh.session.route("GET", "/repos/o/r/pulls/5/comments", _Resp(200, [
        {"path": "a.py", "line": 10, "body": f"{INLINE_MARKER}\nalready"},
        {"path": "a.py", "line": 11, "body": "human comment"},
    ]))
    gh.session.route("POST", "/repos/o/r/pulls/5/reviews", _Resp(200, {"id": 1}))
    posted = gh.post_inline_review("o/r", 5, "sha", [
        {"path": "a.py", "line": 10, "body": "dup"},
        {"path": "a.py", "line": 11, "body": "new one"},
        {"path": "b.py", "line": 3, "body": "another"},
    ])
    assert posted == 2
    review = [c for c in gh.session.calls if c["path"].endswith("/reviews")][0]["json"]
    assert review["commit_id"] == "sha" and review["event"] == "COMMENT"
    assert [(c["path"], c["line"]) for c in review["comments"]] == [("a.py", 11), ("b.py", 3)]
    assert all(c["body"].startswith(INLINE_MARKER) and c["side"] == "RIGHT" for c in review["comments"])


def test_inline_review_all_duplicates_skips(gh):
    gh.session.route("GET", "/repos/o/r/pulls/5/comments", _Resp(200, [{"path": "a.py", "line": 10, "body": INLINE_MARKER}]))
    assert gh.post_inline_review("o/r", 5, "sha", [{"path": "a.py", "line": 10, "body": "x"}]) == 0
    assert [c["method"] for c in gh.session.calls] == ["GET"]


def test_inline_review_empty(gh):
    assert gh.post_inline_review("o/r", 5, "sha", []) == 0
    assert gh.session.calls == []


def test_inline_review_falls_back_per_comment(gh):
    gh.session.route("GET", "/repos/o/r/pulls/5/comments", _Resp(200, []))
    gh.session.route("POST", "/repos/o/r/pulls/5/reviews", _Resp(422, {"message": "line outside diff"}))
    gh.session.route("POST", "/repos/o/r/pulls/5/comments", lambda kw: _Resp(201, {}) if kw["json"]["line"] != 99 else _Resp(422, {}))
    posted = gh.post_inline_review("o/r", 5, "sha", [
        {"path": "a.py", "line": 1, "body": "ok"},
        {"path": "a.py", "line": 99, "body": "outside diff"},
    ])
    assert posted == 1
    singles = [c for c in gh.session.calls if c["path"].endswith("/pulls/5/comments") and c["method"] == "POST"]
    assert len(singles) == 2
    assert singles[0]["json"]["commit_id"] == "sha"

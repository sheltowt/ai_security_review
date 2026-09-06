"""Minimal GitHub REST client for pull-request review runs."""

import os
from typing import Any, Dict, List, Optional

import requests

from ai_security_review.logger import get_logger

logger = get_logger(__name__)

COMMENT_MARKER = "<!-- ai-security-review -->"
INLINE_MARKER = "<!-- ai-security-review:finding -->"


class GitHubClient:
    def __init__(self, token: Optional[str] = None, api_url: Optional[str] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        if not self.token:
            raise ValueError("GITHUB_TOKEN is required for GitHub operations")
        self.api_url = (api_url or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    # ---- reads --------------------------------------------------------------------

    def get_pr(self, repo: str, number: int) -> Dict[str, Any]:
        r = self.session.get(f"{self.api_url}/repos/{repo}/pulls/{number}", timeout=30)
        r.raise_for_status()
        pr = r.json()
        return {
            "repo": repo,
            "number": pr["number"],
            "title": pr.get("title", ""),
            "body": pr.get("body") or "",
            "author": (pr.get("user") or {}).get("login", ""),
            "head_sha": pr["head"]["sha"],
            "base_ref": pr["base"]["ref"],
            "head_ref": pr["head"]["ref"],
        }

    def get_pr_diff(self, repo: str, number: int) -> str:
        r = self.session.get(
            f"{self.api_url}/repos/{repo}/pulls/{number}",
            headers={"Accept": "application/vnd.github.diff"},
            timeout=60,
        )
        r.raise_for_status()
        return r.text

    # ---- writes -------------------------------------------------------------------

    def has_existing_summary(self, repo: str, number: int) -> bool:
        r = self.session.get(f"{self.api_url}/repos/{repo}/issues/{number}/comments", params={"per_page": 100}, timeout=30)
        r.raise_for_status()
        return any(COMMENT_MARKER in (c.get("body") or "") for c in r.json())

    def post_summary_comment(self, repo: str, number: int, body: str, update_existing: bool = True) -> None:
        body = f"{COMMENT_MARKER}\n{body}"
        if update_existing:
            r = self.session.get(f"{self.api_url}/repos/{repo}/issues/{number}/comments", params={"per_page": 100}, timeout=30)
            r.raise_for_status()
            for c in r.json():
                if COMMENT_MARKER in (c.get("body") or ""):
                    u = self.session.patch(f"{self.api_url}/repos/{repo}/issues/comments/{c['id']}", json={"body": body}, timeout=30)
                    u.raise_for_status()
                    logger.info("Updated existing summary comment %s", c["id"])
                    return
        r = self.session.post(f"{self.api_url}/repos/{repo}/issues/{number}/comments", json={"body": body}, timeout=30)
        r.raise_for_status()
        logger.info("Posted summary comment")

    def post_inline_review(self, repo: str, number: int, head_sha: str, comments: List[Dict[str, Any]]) -> int:
        """Post findings as one review with inline comments. Falls back per-comment on failure."""
        if not comments:
            return 0
        existing = self.session.get(f"{self.api_url}/repos/{repo}/pulls/{number}/comments", params={"per_page": 100}, timeout=30)
        existing.raise_for_status()
        already = {(c.get("path"), c.get("line") or c.get("original_line")) for c in existing.json() if INLINE_MARKER in (c.get("body") or "")}
        fresh = [c for c in comments if (c["path"], c["line"]) not in already]
        if not fresh:
            logger.info("All inline findings already commented; skipping")
            return 0
        payload = {
            "commit_id": head_sha,
            "event": "COMMENT",
            "body": "Automated security review findings are attached inline.",
            "comments": [{"path": c["path"], "line": c["line"], "side": "RIGHT", "body": f"{INLINE_MARKER}\n{c['body']}"} for c in fresh],
        }
        r = self.session.post(f"{self.api_url}/repos/{repo}/pulls/{number}/reviews", json=payload, timeout=60)
        if r.ok:
            logger.info("Posted review with %d inline comments", len(fresh))
            return len(fresh)
        logger.warning("Review creation failed (%s): %s; retrying comments individually", r.status_code, r.text[:300])
        posted = 0
        for c in fresh:
            single = {"commit_id": head_sha, "path": c["path"], "line": c["line"], "side": "RIGHT", "body": f"{INLINE_MARKER}\n{c['body']}"}
            s = self.session.post(f"{self.api_url}/repos/{repo}/pulls/{number}/comments", json=single, timeout=30)
            if s.ok:
                posted += 1
            else:
                logger.warning("Could not comment on %s:%s (%s)", c["path"], c["line"], s.status_code)
        return posted

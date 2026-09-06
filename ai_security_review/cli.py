"""Command-line entry point.

Examples::

    # Pending changes on the current branch vs main
    ai-security-review --base main

    # A saved diff
    ai-security-review --diff-file change.patch

    # A GitHub pull request (needs GITHUB_TOKEN); optionally comment back
    ai-security-review --repo owner/name --pr 42 --comment-pr

    # Skip triage and force all three scans through Claude Code
    ai-security-review --base main --scans data,exposure,access --backend claude-code
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from ai_security_review import __version__
from ai_security_review.constants import (
    ALL_SCANS,
    ALL_TOOLS,
    DEFAULT_BACKEND,
    DEFAULT_MIN_FINDING_CONFIDENCE,
    DEFAULT_SCAN_EFFORT,
    DEFAULT_SCAN_MODEL,
    DEFAULT_TOOLS,
    DEFAULT_TRIAGE_CONFIDENCE_THRESHOLD,
    DEFAULT_TRIAGE_EFFORT,
    DEFAULT_TRIAGE_MODEL,
    EXIT_CONFIGURATION_ERROR,
    EXIT_FINDINGS,
    EXIT_RUNTIME_ERROR,
    EXIT_SUCCESS,
    GITLEAKS_CONFIG,
    SEMGREP_CONFIG,
    SEVERITIES,
    TOOL_TIMEOUT_SECONDS,
    VALID_BACKENDS,
)
from ai_security_review.diff import DiffBundle, ExclusionRules, build_bundle, git_diff, git_working_tree_diff
from ai_security_review.logger import get_logger
from ai_security_review.pipeline import PipelineConfig, run_pipeline
from ai_security_review.report import finding_comment_body, render_markdown_summary

logger = get_logger("ai_security_review")


def _parse_scan_list(value: Optional[str]) -> Optional[List[str]]:
    if value is None:
        return None
    keys = [v.strip().lower() for v in value.split(",") if v.strip()]
    bad = [k for k in keys if k not in ALL_SCANS]
    if bad:
        raise argparse.ArgumentTypeError(f"unknown scan(s): {', '.join(bad)}; valid: {', '.join(ALL_SCANS)}")
    return keys


def _parse_tool_list(value: Optional[str]) -> List[str]:
    """Comma-separated tool names; 'none' (or empty) disables external scanners."""
    if value is None:
        return list(DEFAULT_TOOLS)
    keys = [v.strip().lower() for v in value.split(",") if v.strip()]
    if keys == ["none"]:
        return []
    bad = [k for k in keys if k not in ALL_TOOLS]
    if bad:
        raise argparse.ArgumentTypeError(f"unknown tool(s): {', '.join(bad)}; valid: {', '.join(ALL_TOOLS)} or none")
    return keys


def _read_optional_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        logger.warning("Instructions file not found: %s", path)
        return None
    return p.read_text(encoding="utf-8")


def _load_custom_scan_instructions(directory: Optional[str]) -> Dict[str, str]:
    """Load ``<dir>/{data,exposure,access}.{md,txt}`` if present."""
    out: Dict[str, str] = {}
    if not directory:
        return out
    base = Path(directory)
    for key in ALL_SCANS:
        for ext in (".md", ".txt"):
            candidate = base / f"{key}{ext}"
            if candidate.is_file():
                out[key] = candidate.read_text(encoding="utf-8")
                break
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ai-security-review", description="Triage-driven AI security review of a code diff.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    src = p.add_argument_group("diff source (pick one; defaults to working tree vs HEAD)")
    src.add_argument("--diff-file", help="Path to a unified diff file ('-' for stdin)")
    src.add_argument("--base", help="Git ref to diff against (uses merge-base; e.g. main, origin/main)")
    src.add_argument("--head", default="HEAD", help="Git ref for the head side (default: HEAD)")
    src.add_argument("--working-tree", action="store_true", help="Diff uncommitted changes (against --base if given, else HEAD)")
    src.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"), help="GitHub owner/name (default: $GITHUB_REPOSITORY)")
    src.add_argument("--pr", type=int, default=_env_int("PR_NUMBER"), help="Pull request number to fetch from GitHub (default: $PR_NUMBER)")
    src.add_argument("--repo-dir", default=os.environ.get("REPO_PATH") or ".", help="Local checkout used for git and file context (default: .)")

    run = p.add_argument_group("review behaviour")
    run.add_argument("--backend", choices=VALID_BACKENDS, default=DEFAULT_BACKEND, help=f"Scan backend (default: {DEFAULT_BACKEND})")
    run.add_argument("--triage-model", default=DEFAULT_TRIAGE_MODEL)
    run.add_argument("--scan-model", default=DEFAULT_SCAN_MODEL)
    run.add_argument("--triage-effort", default=DEFAULT_TRIAGE_EFFORT, choices=["low", "medium", "high", "xhigh", "max"])
    run.add_argument("--scan-effort", default=DEFAULT_SCAN_EFFORT, choices=["low", "medium", "high", "xhigh", "max"])
    run.add_argument("--scans", type=_parse_scan_list, default=None, help="Skip triage and run exactly these scans (comma-separated: data,exposure,access)")
    run.add_argument("--always-scans", type=_parse_scan_list, default=_parse_scan_list(os.environ.get("ALWAYS_SCANS") or None), help="Scans to run regardless of triage")
    run.add_argument("--triage-threshold", type=float, default=DEFAULT_TRIAGE_CONFIDENCE_THRESHOLD, help="Minimum triage confidence for a scan to run")
    run.add_argument("--min-confidence", type=float, default=DEFAULT_MIN_FINDING_CONFIDENCE, help="Drop findings below this confidence")
    run.add_argument("--exclude-dirs", default=os.environ.get("EXCLUDE_DIRECTORIES", ""), help="Comma-separated directories to ignore")
    run.add_argument("--triage-instructions", default=os.environ.get("CUSTOM_TRIAGE_INSTRUCTIONS") or None, help="File with extra triage instructions")
    run.add_argument("--scan-instructions-dir", default=os.environ.get("CUSTOM_SCAN_INSTRUCTIONS_DIR") or None, help="Directory with data.md / exposure.md / access.md extra instructions")
    run.add_argument("--no-context-files", action="store_true", help="Do not attach post-change file contents (API backend)")
    run.add_argument("--allow-findings-outside-diff", action="store_true", help="Keep findings in files not touched by the diff")

    tools = p.add_argument_group("external scanners (run before triage; missing binaries are skipped)")
    tools.add_argument("--tools", type=_parse_tool_list, default=_parse_tool_list(os.environ.get("AI_SECURITY_REVIEW_TOOLS")), help=f"Comma-separated scanners to run: {', '.join(ALL_TOOLS)}, or none (default: {','.join(DEFAULT_TOOLS) or 'none'})")
    tools.add_argument("--tool-timeout", type=int, default=TOOL_TIMEOUT_SECONDS, help="Per-scanner timeout in seconds")
    tools.add_argument("--semgrep-config", default=SEMGREP_CONFIG, help="Semgrep ruleset or rules path (default: %(default)s)")
    tools.add_argument("--gitleaks-config", default=GITLEAKS_CONFIG, help="Path to a gitleaks TOML config (default: the repository's .gitleaks.toml or gitleaks' built-in rules)")

    out = p.add_argument_group("output")
    out.add_argument("--output", default=os.environ.get("RESULTS_FILE") or "security-review-results.json", help="Where to write the JSON results")
    out.add_argument("--summary-file", default=os.environ.get("SUMMARY_FILE") or None, help="Also write the Markdown summary here")
    out.add_argument("--print-json", action="store_true", help="Print the full JSON result to stdout")
    out.add_argument("--comment-pr", action="store_true", default=_env_bool("COMMENT_PR"), help="Post the summary and inline findings to the PR (needs --repo/--pr and GITHUB_TOKEN)")
    out.add_argument("--fail-on", default=os.environ.get("FAIL_ON_SEVERITY", "HIGH"), help="Exit non-zero when a finding at or above this severity is kept (HIGH|MEDIUM|LOW|NONE)")
    return p


def _env_int(name: str) -> Optional[int]:
    value = os.environ.get(name)
    try:
        return int(value) if value else None
    except ValueError:
        return None


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


def acquire_diff(args: argparse.Namespace, rules: ExclusionRules):
    """Return ``(bundle, pr_context)`` for the chosen diff source."""
    repo_dir = Path(args.repo_dir).resolve()
    pr_context = None

    if args.diff_file:
        text = sys.stdin.read() if args.diff_file == "-" else Path(args.diff_file).read_text(encoding="utf-8")
    elif args.pr and args.repo:
        from ai_security_review.github_client import GitHubClient

        gh = GitHubClient()
        pr_context = gh.get_pr(args.repo, args.pr)
        text = gh.get_pr_diff(args.repo, args.pr)
    elif args.working_tree or not args.base:
        text = git_working_tree_diff(repo_dir, args.base)
    else:
        text = git_diff(repo_dir, args.base, args.head)

    return build_bundle(text, rules), pr_context


def _fail_threshold(value: str) -> Optional[int]:
    value = (value or "HIGH").upper()
    if value == "NONE":
        return None
    if value not in SEVERITIES:
        raise ValueError(f"--fail-on must be one of {', '.join(SEVERITIES)} or NONE")
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[value]


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        fail_rank = _fail_threshold(args.fail_on)
    except ValueError as e:
        parser.error(str(e))

    rules = ExclusionRules([d for d in (args.exclude_dirs or "").split(",") if d.strip()])
    try:
        bundle, pr_context = acquire_diff(args, rules)
    except Exception as e:
        logger.error("Could not obtain diff: %s", e)
        _write_json(args.output, {"error": f"Could not obtain diff: {e}"})
        return EXIT_CONFIGURATION_ERROR

    logger.info("Reviewing %d file(s) (%d excluded); scanners: %s", len(bundle.files), len(bundle.excluded), ",".join(args.tools) or "none")

    config = PipelineConfig(
        repo_dir=Path(args.repo_dir).resolve(),
        backend=args.backend,
        triage_model=args.triage_model,
        scan_model=args.scan_model,
        triage_effort=args.triage_effort,
        scan_effort=args.scan_effort,
        triage_threshold=args.triage_threshold,
        min_confidence=args.min_confidence,
        forced_scans=args.scans,
        always_scans=args.always_scans or [],
        exclude_dirs=rules.exclude_dirs,
        custom_triage_instructions=_read_optional_file(args.triage_instructions),
        custom_scan_instructions=_load_custom_scan_instructions(args.scan_instructions_dir),
        include_context_files=not args.no_context_files,
        require_in_diff=not args.allow_findings_outside_diff,
        tools=args.tools,
        tool_timeout=args.tool_timeout,
        tool_options={"semgrep_config": args.semgrep_config, "gitleaks_config": args.gitleaks_config},
    )

    try:
        result = run_pipeline(config, bundle, pr_context)
    except Exception as e:  # last-resort guard so the action always gets a results file
        logger.exception("Review crashed")
        _write_json(args.output, {"error": f"Review crashed: {e}"})
        return EXIT_RUNTIME_ERROR

    _write_json(args.output, result)
    summary_md = render_markdown_summary(result)
    if args.summary_file:
        Path(args.summary_file).write_text(summary_md, encoding="utf-8")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary_md + "\n")

    if args.print_json:
        print(json.dumps(result, indent=2))
    else:
        print(summary_md)

    if args.comment_pr and pr_context:
        _comment_on_pr(pr_context, result, summary_md)
    elif args.comment_pr:
        logger.warning("--comment-pr given but no PR context (need --repo and --pr)")

    _emit_github_outputs(args.output, result)

    if result.get("error") and not result.get("findings"):
        return EXIT_RUNTIME_ERROR
    if fail_rank is not None:
        rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if any(rank.get(f.get("severity"), 0) >= fail_rank for f in result.get("findings", [])):
            return EXIT_FINDINGS
    return EXIT_SUCCESS


def _comment_on_pr(pr_context: Dict, result: Dict, summary_md: str) -> None:
    from ai_security_review.github_client import GitHubClient

    try:
        gh = GitHubClient()
        gh.post_summary_comment(pr_context["repo"], pr_context["number"], summary_md)
        inline = [{"path": f["file"], "line": f["line"], "body": finding_comment_body(f)} for f in result.get("findings", [])]
        gh.post_inline_review(pr_context["repo"], pr_context["number"], pr_context["head_sha"], inline)
    except Exception as e:
        logger.error("Failed to comment on PR: %s", e)


def _emit_github_outputs(results_file: str, result: Dict) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    counts = result.get("severity_counts") or {}
    triage = result.get("triage") or {}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"findings-count={len(result.get('findings') or [])}\n")
        fh.write(f"high-count={counts.get('HIGH', 0)}\n")
        fh.write(f"risk-level={triage.get('risk_level', 'unknown')}\n")
        fh.write(f"selected-scans={','.join(triage.get('selected_scans') or [])}\n")
        fh.write(f"tools-run={','.join(t['tool'] for t in (result.get('tool_results') or []) if t.get('status') == 'completed')}\n")
        fh.write(f"results-file={results_file}\n")


def _write_json(path: str, data: Dict) -> None:
    try:
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError as e:
        logger.error("Could not write %s: %s", path, e)


if __name__ == "__main__":
    sys.exit(main())

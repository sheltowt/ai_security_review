# Triaged AI Security Review

An AI-powered security review for code changes, modelled on
[anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review)
with one structural difference: **a model triages the diff first, and only the relevant scans run.**

```
            gitleaks ──▶ secret findings ───────────────────────────────┐
            semgrep  ──▶ candidates ──┐                                 │
                                      ▼                                 ▼
                         ┌──────────────┐
   diff ──▶ triage ──▶   │ data scan    │ ──┐
            (1 call)     ├──────────────┤   │
            picks 0–3    │ exposure scan│ ──┼──▶ filter + dedupe ──▶ report / PR comments
            of:          ├──────────────┤   │
                         │ access scan  │ ──┘  (scans confirm or dismiss the candidates)
                         └──────────────┘
```

Each scan answers exactly one question:

| Scan | Question | Examples |
|---|---|---|
| **Data** | Is data handled safely? | SQL/command/template injection, deserialisation, path traversal, weak crypto, PII storage, unverified webhooks |
| **Exposure** | What does this reveal? | hardcoded secrets, tokens in logs, verbose errors, new unauthenticated routes, XSS, permissive CORS, public buckets, supply chain |
| **Access** | Who is allowed to do it? | auth bypass, missing permission checks, IDOR, tenant isolation, JWT validation, privilege escalation, CSRF, over-broad IAM |

The scans have explicit hand-off rules so the same bug is not reported three times, and findings that two
scans both catch are merged. Full definitions are in [docs/scans.md](docs/scans.md).

Two open-source scanners run alongside the model, when installed: **gitleaks** reports hardcoded secrets
directly (and flags secrets this change *removes*, which are still in git history), and **Semgrep** hits
become candidates that the owning scan confirms or dismisses, so static-analysis noise never reaches the PR
without a model tracing the flow first. See [docs/tools.md](docs/tools.md).

## Why triage first

Most diffs do not touch all three areas. A docs change needs no scan; a new endpoint usually needs exposure
and access but not data; a query refactor needs data only. Triage is a single, cheaper, structured call that
routes the change, produces a focus list for each scan it selects, and gives reviewers a plain-language
summary of the risk even when no scan runs. Scans run in parallel, so the wall-clock cost is one triage call
plus the slowest selected scan.

## Quick start: GitHub Action

```yaml
name: Security Review

permissions:
  contents: read
  pull-requests: write   # for PR comments

on:
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0
      - uses: sheltowt/ai_security_review@main
        with:
          claude-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          comment-pr: true
          # fail-on-severity: HIGH        # gate merges on HIGH findings
          # backend: claude-code          # let scans explore the repo
          # scan-instructions-dir: .security-review
          # tools: gitleaks,semgrep       # gitleaks is on by default; semgrep adds ~1 min of install
```

The action posts one summary comment (triage table plus findings, updated in place on re-runs) and inline
review comments on the offending lines. Results are also uploaded as a workflow artifact and written to the
job summary.

### Action inputs

| Input | Default | Description |
|---|---|---|
| `claude-api-key` | required | Anthropic API key |
| `backend` | `api` | `api` (Messages API, diff + touched files) or `claude-code` (headless Claude Code with read-only repo tools) |
| `triage-model` / `scan-model` | `claude-opus-5` | Models per stage |
| `triage-effort` / `scan-effort` | `medium` / `high` | Effort per stage |
| `scans` | `` | Skip triage and run exactly these (`data,exposure,access`) |
| `always-scans` | `` | Run these regardless of triage |
| `triage-threshold` | `0.5` | Minimum triage confidence for a scan to run |
| `min-confidence` | `0.7` | Drop findings below this confidence |
| `exclude-directories` | `` | Comma-separated directories to ignore |
| `triage-instructions` | `` | File with extra triage guidance |
| `scan-instructions-dir` | `` | Directory with `data.md` / `exposure.md` / `access.md` |
| `comment-pr` | `true` | Post summary and inline comments |
| `fail-on-severity` | `NONE` | Fail the step at or above this severity |
| `upload-results` | `true` | Upload results as an artifact |
| `tools` | `gitleaks` | Open-source scanners to run (`gitleaks,semgrep`) or `none` |
| `install-tools` | `true` | Install listed scanners that are missing (gitleaks from a pinned, checksum-verified release; semgrep via pip) |
| `gitleaks-version` / `semgrep-version` | `8.30.1` / latest | Versions to install |
| `semgrep-config` | `p/default` | Semgrep ruleset or rules path |

Outputs: `findings-count`, `high-count`, `risk-level`, `selected-scans`, `tools-run`, `results-file`.

## Quick start: command line

```bash
pip install git+https://github.com/sheltowt/ai_security_review
export ANTHROPIC_API_KEY=...

# Review the current branch against main
ai-security-review --base main

# Review a saved diff
ai-security-review --diff-file change.patch

# Review a GitHub PR and comment on it
GITHUB_TOKEN=... ai-security-review --repo owner/name --pr 42 --comment-pr

# Skip triage, force all three scans, let them explore the repo through Claude Code
ai-security-review --base main --scans data,exposure,access --backend claude-code

# Run without external scanners, or with a custom Semgrep ruleset
ai-security-review --base main --tools none
ai-security-review --base main --tools gitleaks,semgrep --semgrep-config p/owasp-top-ten
```

The CLI prints a Markdown summary and writes `security-review-results.json`. Run `ai-security-review --help`
for every option; [docs/customizing.md](docs/customizing.md) explains how to steer triage and each scan.

## Claude Code slash command

`.claude/commands/triaged-security-review.md` provides `/triaged-security-review`, which runs the same
triage-then-scan flow interactively inside Claude Code on your pending changes, using subagents for the
scans. Copy it into your project's `.claude/commands/` to use it there.

## Output format

`security-review-results.json`:

```jsonc
{
  "triage": {
    "summary": "Adds an export endpoint that builds SQL from the path and logs the auth header.",
    "risk_level": "high", "change_kind": "feature",
    "scans": {
      "data":     {"relevant": true,  "confidence": 0.9, "reason": "...", "focus": ["app/api/users.py: export_user query"]},
      "exposure": {"relevant": true,  "confidence": 0.8, "reason": "...", "focus": ["app/api/users.py: logger.info"]},
      "access":   {"relevant": false, "confidence": 0.3, "reason": "...", "focus": []}
    },
    "selected_scans": ["data", "exposure"]
  },
  "tool_results": [{"tool": "gitleaks", "status": "completed", "version": "8.30.1", "findings_count": 0, "candidates_count": 0, ...}],
  "scan_results": [{"scan": "data", "status": "completed", "findings_count": 1, "candidate_verdicts": [], "duration_seconds": 41.2, ...}],
  "findings": [{
    "file": "app/api/users.py", "line": 15, "severity": "HIGH", "category": "sql_injection",
    "title": "SQL injection in export_user", "description": "...", "exploit_scenario": "...",
    "recommendation": "...", "confidence": 0.95, "introduced_by_change": true, "scans": ["data"]
  }],
  "severity_counts": {"HIGH": 1, "MEDIUM": 1, "LOW": 0},
  "filter_summary": {"total": 3, "kept": 2, "excluded_low_confidence": 1, "merged_duplicates": 0, "candidates_total": 0, "candidates_confirmed": 0, "candidates_dismissed": 0, "candidates_unverified": 0, "excluded_details": [...]},
  "usage": {"input_tokens": 48210, "output_tokens": 3120}
}
```

## How it works

```
ai_security_review/
├── cli.py            # argument parsing, diff source selection, outputs, exit codes
├── pipeline.py       # diff -> triage -> scans -> filter -> result
├── diff.py           # git / file / GitHub diff acquisition, exclusion rules, hunk parsing
├── triage.py         # the triage call and scan selection
├── scans.py          # the three scan definitions (scope, hand-offs, signals) + finding schema
├── prompts.py        # triage and scan prompt builders
├── scan_runner.py    # runs scans in parallel through the API or Claude Code
├── claude_client.py  # Messages API wrapper: structured output, retries, refusal handling
├── findings.py       # normalisation, hard exclusions, confidence filter, cross-scan dedupe
├── github_client.py  # PR data, diff, summary + inline review comments
├── report.py         # Markdown rendering
├── tools/            # open-source scanners: gitleaks (secrets), semgrep (SAST candidates), CWE -> category map
└── tests/
```

1. **Diff acquisition.** From a file, a git range, the working tree, or the GitHub API. Generated files,
   lockfiles, and excluded directories are dropped before any model sees the diff.
2. **Scanners.** gitleaks and Semgrep run in parallel on the touched files, restricted to added lines. Secret
   hits are findings; Semgrep hits are candidates mapped by CWE to the scan that owns them. Missing binaries
   are skipped.
3. **Triage.** One structured-output call returns a summary, risk level, and per-scan relevance with confidence
   and a focus list. Scanner output is included as routing hints. Scans at or above the threshold are selected;
   `--always-scans` can add more, and any scan that owns a candidate is added so it can give a verdict.
4. **Scans.** Each selected scan gets its own system prompt (scope, hand-offs, signals, exclusions, rubric),
   the triage focus, and its candidates to confirm or dismiss. With the `api` backend the scan also receives the
   post-change contents of touched files; with `claude-code` it can explore the repository with read-only tools.
   Scans run concurrently.
5. **Filtering.** Candidates are resolved against the verdicts. Findings are normalised, hard-excluded classes
   removed, low-confidence and out-of-diff findings dropped, and near-duplicates across scans and scanners
   merged (keeping the stronger write-up and tagging every source).
6. **Reporting.** JSON results, a Markdown summary, GitHub job summary, and optional PR comments.

Model calls use structured outputs so the JSON always matches the schema, and opt into Anthropic's
server-side refusal fallback so a safety-classifier decline on a security-flavoured prompt is retried on a
substitute model automatically.

## Security considerations

This tool sends the diff and touched files to the Anthropic API. It is not hardened against prompt injection
in the code under review, so run it only on trusted pull requests; for public repositories, require approval
for workflows from external contributors. The `claude-code` backend runs with read-only tools, but a
malicious repository could still try to steer the model through file contents.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

Tests use a fake client; nothing hits the network.

## License

MIT

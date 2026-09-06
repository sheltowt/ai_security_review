# Customising the review

## Steering triage

Give triage project context so it routes better. Pass a text file via `--triage-instructions` (CLI) or
`triage-instructions` (action). Examples of useful content:

- "Everything under `billing/` and `payments/` is high risk; always run the data and access scans for it."
- "`internal/tools/` is only reachable from the corporate VPN; treat exposure findings there as low priority."
- "We use Django with the ORM everywhere; raw SQL is a red flag."

## Steering a specific scan

Put `data.md`, `exposure.md`, and/or `access.md` in a directory and point `--scan-instructions-dir`
(or the `scan-instructions-dir` action input) at it. Each file is appended to that scan's system prompt.
See `examples/custom-instructions/` for starting points. Good uses:

- Naming the project's sanitisation helpers and authorisation decorators so the scan recognises them as mitigations.
- Describing the tenancy model (what the tenant key is, where it is enforced).
- Listing known-accepted patterns so they are not re-reported.

## Forcing or adding scans

- `--scans data,exposure,access` skips triage and runs exactly those scans. Useful for security-sensitive
  repositories where the routing decision is not worth the saved cost.
- `--always-scans access` keeps triage but guarantees the access scan runs on every change.
- `--triage-threshold 0.3` runs scans the model was less sure about (default 0.5).

## Backends

- `api` (default): one Messages API call per scan. The scan sees the diff plus the post-change contents of
  touched files. Fast and cheap; no tool use.
- `claude-code`: runs each scan as a headless `claude -p` session with read-only tools, so the model can
  explore the repository to trace inputs and find existing mitigations. Slower and more thorough. Needs the
  Claude Code CLI on `PATH` and an API key that is enabled for Claude Code.

## Scanners

`--tools gitleaks,semgrep` (the default) runs the open-source scanners that are installed; `--tools none`
disables them. gitleaks findings are reported directly. Semgrep hits are handed to the owning scan as
candidates, and only reported once confirmed or when the rule's own confidence clears `--min-confidence`.
Details, including how `.gitleaksignore` and custom rulesets are honoured, are in [tools.md](tools.md).

## Filtering

- `--min-confidence` (default 0.7) drops low-confidence findings.
- Findings in files outside the diff are dropped unless `--allow-findings-outside-diff` is set.
- `--exclude-dirs vendor,generated` removes directories from both the diff and the findings.
- Hard exclusion rules in `ai_security_review/findings.py` remove finding classes that are never wanted
  (DoS, rate limiting, resource leaks, memory-safety in safe languages, documentation files).

## Exit codes and gating

`--fail-on HIGH` (the CLI default) exits 1 when a HIGH finding survives filtering; `MEDIUM` or `LOW`
lower the bar; `NONE` never fails on findings. The action defaults to `NONE` so it reports without blocking;
set `fail-on-severity: HIGH` to gate merges.

Other exit codes: 2 for configuration errors (no diff, bad arguments), 3 when the review could not run
(triage failed, every scan failed).

## Environment variables

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | API key (or use `ant auth login` / `ANTHROPIC_AUTH_TOKEN`). |
| `AI_SECURITY_REVIEW_MODEL` | Default model for both triage and scans. |
| `AI_SECURITY_REVIEW_TRIAGE_MODEL`, `AI_SECURITY_REVIEW_SCAN_MODEL` | Override per stage. |
| `AI_SECURITY_REVIEW_TRIAGE_EFFORT`, `AI_SECURITY_REVIEW_SCAN_EFFORT` | Effort levels. |
| `AI_SECURITY_REVIEW_BACKEND` | `api` or `claude-code`. |
| `AI_SECURITY_REVIEW_REFUSAL_FALLBACK` | `false` disables the server-side refusal fallback. |
| `AI_SECURITY_REVIEW_CLAUDE_CODE_TIMEOUT` | Per-scan timeout in seconds for the claude-code backend. |
| `AI_SECURITY_REVIEW_TOOLS` | Default scanners (`gitleaks,semgrep`, or `none`). See [tools.md](tools.md). |
| `AI_SECURITY_REVIEW_TOOL_TIMEOUT` | Per-scanner timeout in seconds. |
| `AI_SECURITY_REVIEW_SEMGREP_CONFIG`, `AI_SECURITY_REVIEW_GITLEAKS_CONFIG` | Semgrep ruleset; gitleaks rules file. |
| `AI_SECURITY_REVIEW_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`. |
| `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `PR_NUMBER` | Used when reviewing a pull request. |

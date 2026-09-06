# Open-source scanners

Two deterministic scanners run alongside the model scans. They are cheap, fast, and precise in ways a
model is not, and the model is good at the one thing they are bad at: deciding whether a pattern match
is actually exploitable here.

```
             ┌──────────┐  findings (secrets)  ─────────────────────────────┐
   diff ──▶  │ gitleaks │                                                   │
             └──────────┘                                                   ▼
             ┌──────────┐  candidates ──▶ triage ──▶ owning scan ──▶ verdict ──▶ filter + dedupe ──▶ report
   diff ──▶  │ semgrep  │       │          (signals)   (confirm / dismiss / unsure)
             └──────────┘       └──────────────── auto-selects the owning scan
```

| Tool | Licence | What it does here | How its output is treated |
|---|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Secret detection on the touched files | **Reported directly.** A model cannot verify a credential, and the regex rules are precise. |
| [Semgrep](https://semgrep.dev) / [Opengrep](https://github.com/opengrep/opengrep) | LGPL engine | Static analysis with a security ruleset | **Candidates.** The scan that owns the category confirms or dismisses each one. |

Both run in parallel before triage, on the post-change contents of the touched files only. Hits on lines
the diff did not add are ignored, matching the rule that the review is of the *change*. A scanner that is
not installed is `skipped`; one that crashes or times out is `failed`. Neither stops the review.

## gitleaks

The touched files are copied into a temporary tree and scanned with `gitleaks dir`, which needs gitleaks
8.19 or newer (the action installs 8.30.1). Two kinds of finding come out:

- **`hardcoded_secret`** (HIGH, confidence 0.85): a rule matched on a line this change added.
- **`secret_in_history`** (MEDIUM, confidence 0.8): a rule matched on a line this change *removed*.
  Deleting a secret from a file does not delete it from git history, so the finding asks for rotation.
  A secret that merely moved is reported once, as the added-side finding.

Secret values never reach the model, the results file, or a PR comment: gitleaks runs with `--redact`,
and the finding text carries only the rule id and description. Unlike other findings, a secret in a
Markdown or text file is still reported.

The repository's own `.gitleaks.toml` and `.gitleaksignore` are honoured. Fingerprints in
`.gitleaksignore` are rewritten to match the staged copy, so an entry such as
`app/config.py:aws-access-token:12` still applies. `--gitleaks-config` (or
`AI_SECURITY_REVIEW_GITLEAKS_CONFIG`) points at a different rules file.

## Semgrep

Semgrep runs with `--metrics=off` on the touched files using the ruleset in `--semgrep-config`
(default `p/default`; `AI_SECURITY_REVIEW_SEMGREP_CONFIG` also works). Registry rulesets (`p/...`)
are downloaded from semgrep.dev on every run, so an offline or egress-restricted runner reports the tool
as `failed`; point `--semgrep-config` at a rules file or directory in the repository to run without
network access. Avoid `auto`, which sends project metadata to semgrep.dev. If `opengrep` is on the
PATH and `semgrep` is not, it is used with the same flags.

Each security-category hit on an added line becomes a candidate:

1. The rule's CWE is mapped to one of the review's finding categories (`CWE-89` becomes
   `sql_injection`, `CWE-798` becomes `hardcoded_secret`, and so on; see `tools/categories.py`).
   That category belongs to exactly one scan, which becomes the candidate's owner.
2. The rule's own confidence metadata sets a starting confidence: HIGH 0.8, MEDIUM 0.65, LOW 0.5,
   nudged up for `vuln` rules and down for `audit` rules. Most registry rules are LOW and `audit`, so
   they start well below the reporting threshold.
3. Several rules on the same line collapse into one candidate, and a candidate that duplicates a
   gitleaks finding is dropped.
4. Triage sees the candidates as routing signals. Whatever triage decides, the owning scan of any
   candidate is selected so that someone gives a verdict.
5. The owning scan receives the candidate with its matched source (except for secrets) and returns
   `confirmed`, `dismissed`, or `unsure` with a reason. A confirmed candidate is reported at confidence
   0.85 or the rule's own, whichever is higher, and merged with the model's own write-up of the same
   line if there is one. A dismissed candidate is listed in the filter summary with the model's reason.
   An unsure or unverified candidate (the owning scan was unsure, failed, or was not run) is capped at
   confidence 0.6, below the default `--min-confidence` of 0.7, so a pattern match is never posted on
   its own. Lowering `--min-confidence` to 0.6 is the explicit way to see them. With `--scans`, forced
   means forced: candidates whose owner was not forced are listed in the filter summary and not sent
   to any scan.

Classes the review never reports (denial of service, ReDoS, resource leaks, open redirects) are dropped
at the tool level by CWE, before they cost any tokens.

Licensing note: the Semgrep engine is LGPL, but many registry rules are published under the Semgrep
Rules License, which restricts their use in competing commercial products. Running them in CI on your
own code is fine. Opengrep ships LGPL rules and accepts the same flags if that matters to you.

## Configuration

| Where | Setting | Default |
|---|---|---|
| CLI | `--tools gitleaks,semgrep` or `--tools none` | `gitleaks,semgrep` |
| CLI | `--tool-timeout` seconds | 300 |
| CLI | `--semgrep-config`, `--gitleaks-config` | `p/default`, none |
| Env | `AI_SECURITY_REVIEW_TOOLS`, `AI_SECURITY_REVIEW_TOOL_TIMEOUT`, `AI_SECURITY_REVIEW_SEMGREP_CONFIG`, `AI_SECURITY_REVIEW_GITLEAKS_CONFIG` | as above |
| Action | `tools` | `gitleaks` |
| Action | `install-tools`, `gitleaks-version`, `semgrep-version`, `semgrep-config` | `true`, `8.30.1`, latest, `p/default` |

The action installs gitleaks from the pinned GitHub release and verifies the tarball against the
release's checksums file. Semgrep is installed with pip and adds roughly a minute to the job, which is
why it is opt-in there: set `tools: gitleaks,semgrep` to enable it.

## Output

`security-review-results.json` gains a `tool_results` list and candidate counts in `filter_summary`:

```jsonc
"tool_results": [
  {"tool": "gitleaks", "status": "completed", "version": "8.30.1", "findings_count": 1, "candidates_count": 0, "notes": "...", "error": null, "duration_seconds": 0.1},
  {"tool": "semgrep",  "status": "skipped",   "version": null,     "findings_count": 0, "candidates_count": 0, "notes": "'semgrep' not found on PATH", "error": null, "duration_seconds": 0.0}
],
"filter_summary": {"candidates_total": 3, "candidates_confirmed": 1, "candidates_dismissed": 1, "candidates_unverified": 1, ...}
```

Findings that came from or were confirmed against a scanner carry `tool`, `rule_id`, and (for Semgrep)
`cwe`, and list every source in `scans`, for example `["data", "semgrep"]`. The Markdown summary adds a
Scanners table, and each finding shows the rule that matched.

## Adding another scanner

Subclass `ai_security_review.tools.base.Tool`, set `key` and `binaries`, implement `scan()` to return a
`ToolResult` with `findings` (report directly) and/or `candidates` (needs a verdict; set `owner_scan`),
and register it in `ai_security_review/tools/__init__.py`. Natural next additions are
[OSV-Scanner](https://github.com/google/osv-scanner) for lockfiles, which the diff filter currently
drops before any scan sees them, and [Checkov](https://github.com/bridgecrewio/checkov) or Trivy for
infrastructure files.

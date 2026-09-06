"""Constants and environment-derived defaults."""

import os

# Models. Triage is a single structured call; scans do the heavy lifting.
DEFAULT_MODEL = os.environ.get("AI_SECURITY_REVIEW_MODEL") or "claude-opus-5"
DEFAULT_TRIAGE_MODEL = os.environ.get("AI_SECURITY_REVIEW_TRIAGE_MODEL") or DEFAULT_MODEL
DEFAULT_SCAN_MODEL = os.environ.get("AI_SECURITY_REVIEW_SCAN_MODEL") or DEFAULT_MODEL

# Effort levels passed through output_config.effort. Triage is a routing
# decision; scans are the intelligence-sensitive part.
DEFAULT_TRIAGE_EFFORT = os.environ.get("AI_SECURITY_REVIEW_TRIAGE_EFFORT") or "medium"
DEFAULT_SCAN_EFFORT = os.environ.get("AI_SECURITY_REVIEW_SCAN_EFFORT") or "high"

# Scan backends
BACKEND_CLAUDE_CODE = "claude-code"  # `claude -p` subprocess, can explore the repo
BACKEND_API = "api"                  # direct Messages API call with diff + file context
DEFAULT_BACKEND = os.environ.get("AI_SECURITY_REVIEW_BACKEND") or BACKEND_API
VALID_BACKENDS = (BACKEND_CLAUDE_CODE, BACKEND_API)

# Scan identifiers
SCAN_DATA = "data"
SCAN_EXPOSURE = "exposure"
SCAN_ACCESS = "access"
ALL_SCANS = (SCAN_DATA, SCAN_EXPOSURE, SCAN_ACCESS)

# Triage thresholds
DEFAULT_TRIAGE_CONFIDENCE_THRESHOLD = 0.5   # a scan runs when its relevance confidence >= this
DEFAULT_MIN_FINDING_CONFIDENCE = 0.7        # findings below this are dropped

# API call tuning
API_TIMEOUT_SECONDS = 600
API_MAX_RETRIES = 3
TRIAGE_MAX_TOKENS = 4096
SCAN_MAX_TOKENS = 16000
ENABLE_REFUSAL_FALLBACK = (os.environ.get("AI_SECURITY_REVIEW_REFUSAL_FALLBACK", "true").lower() == "true")
REFUSAL_FALLBACK_BETA = "server-side-fallback-2026-07-01"

# Claude Code subprocess tuning
CLAUDE_CODE_TIMEOUT_SECONDS = int(os.environ.get("AI_SECURITY_REVIEW_CLAUDE_CODE_TIMEOUT", "1200"))
CLAUDE_CODE_ALLOWED_TOOLS = "Read,Glob,Grep,LS,Bash(git diff:*),Bash(git log:*),Bash(git show:*),Bash(git blame:*)"

# External open-source scanners. They run before triage; missing binaries are skipped, never fatal.
TOOL_GITLEAKS = "gitleaks"
TOOL_SEMGREP = "semgrep"
ALL_TOOLS = (TOOL_GITLEAKS, TOOL_SEMGREP)
DEFAULT_TOOLS = tuple(
    t.strip().lower() for t in (os.environ.get("AI_SECURITY_REVIEW_TOOLS") or "gitleaks,semgrep").split(",") if t.strip()
)
TOOL_TIMEOUT_SECONDS = int(os.environ.get("AI_SECURITY_REVIEW_TOOL_TIMEOUT", "300"))
SEMGREP_CONFIG = os.environ.get("AI_SECURITY_REVIEW_SEMGREP_CONFIG") or "p/default"
GITLEAKS_CONFIG = os.environ.get("AI_SECURITY_REVIEW_GITLEAKS_CONFIG") or None
# Confidence assigned to deterministic secret hits. Above the default finding threshold so they report
# without model confirmation; a model cannot verify a credential anyway.
SECRET_FINDING_CONFIDENCE = 0.85
SECRET_IN_HISTORY_CONFIDENCE = 0.8
# Confidence a SAST candidate receives once a scan confirms it.
CONFIRMED_CANDIDATE_CONFIDENCE = 0.85

# Size limits
MAX_DIFF_CHARS = 400_000         # above this the diff is truncated per file for the API backend
MAX_CONTEXT_FILE_CHARS = 60_000  # per file when attaching touched-file contents
MAX_CONTEXT_TOTAL_CHARS = 300_000

# Exit codes
EXIT_SUCCESS = 0
EXIT_FINDINGS = 1
EXIT_CONFIGURATION_ERROR = 2
EXIT_RUNTIME_ERROR = 3

SEVERITIES = ("HIGH", "MEDIUM", "LOW")

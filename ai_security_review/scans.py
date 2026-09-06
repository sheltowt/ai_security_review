"""Definitions of the three targeted scans: data, exposure, access.

Each scan owns a distinct question about the change:

- data:     "Is data handled safely?"   untrusted input reaching sinks, integrity, crypto, storage
- exposure: "What does this reveal?"    secrets, leaks, new attack surface, client-side output
- access:   "Who is allowed to do it?"  authentication, authorization, tenancy, privilege

The boundaries are spelled out per scan so the same bug is not reported three times
and so the triage model has crisp criteria for deciding which scans to run.
"""

from dataclasses import dataclass, field
from typing import Dict, List

from ai_security_review.constants import SCAN_ACCESS, SCAN_DATA, SCAN_EXPOSURE


@dataclass(frozen=True)
class ScanDefinition:
    key: str
    title: str
    question: str                       # the one question this scan answers
    triage_hint: str                    # when the triage model should mark it relevant
    categories: List[str]               # in-scope vulnerability classes (used as finding categories)
    in_scope: List[str]                 # prose bullets for the scan prompt
    hand_off: Dict[str, str] = field(default_factory=dict)  # sibling scan -> what to leave to it
    signals: List[str] = field(default_factory=list)        # code-level cues worth looking for


DATA_SCAN = ScanDefinition(
    key=SCAN_DATA,
    title="Data handling",
    question="Does this change let untrusted or sensitive data be processed, stored, or transformed unsafely?",
    triage_hint=(
        "The change parses, validates, transforms, queries, serializes, stores, encrypts, or moves data; "
        "touches database/ORM code, file I/O, deserialization, templating, shell or process execution, "
        "cryptography, PII handling, or data pipelines."
    ),
    categories=[
        "sql_injection", "nosql_injection", "command_injection", "code_injection", "template_injection",
        "ldap_or_xpath_injection", "xxe", "unsafe_deserialization", "path_traversal",
        "missing_input_validation_with_impact", "type_confusion_or_coercion",
        "weak_cryptography", "insecure_randomness", "improper_key_or_iv_handling",
        "sensitive_data_at_rest_unprotected", "sensitive_data_in_transit_unprotected",
        "data_integrity_or_tampering", "mass_assignment", "unsafe_file_upload_handling",
        "pii_mishandling",
    ],
    in_scope=[
        "Untrusted input flowing into interpreters: SQL/NoSQL queries, shell commands, eval/exec, templates, LDAP/XPath, regex compiled from input.",
        "Deserialization of attacker-controlled bytes (pickle, YAML load, Java/PHP object streams, JSON with type hints).",
        "Path construction from input for reads, writes, includes, archive extraction (zip-slip), or uploads.",
        "Cryptographic misuse: deprecated algorithms, ECB mode, static or predictable IVs/nonces/salts, non-CSPRNG for security values, homegrown crypto, key material derived from weak input.",
        "Sensitive data (credentials, tokens, PII, financial, health) written to storage, caches, queues, or third parties without the protection the surrounding code applies elsewhere.",
        "Integrity: unsigned or unverified data trusted for decisions (webhooks without signature checks, unverified JWT payloads used as data, tampered client-side prices/quantities).",
        "Mass assignment / over-permissive binding of request bodies onto models.",
        "Numeric and type-coercion edge cases that change security-relevant data (negative amounts, overflow used for bypass, truthy string checks).",
    ],
    hand_off={
        SCAN_EXPOSURE: "Whether secrets or data are *revealed* (logs, responses, errors, hardcoded keys) - leave that to the exposure scan.",
        SCAN_ACCESS: "Whether the caller was *allowed* to perform the operation at all - leave authn/authz to the access scan.",
    },
    signals=[
        "string formatting/concatenation into query or command strings",
        "subprocess/os.system/child_process/Runtime.exec with variables",
        "pickle.loads, yaml.load, ObjectInputStream, unserialize, Marshal.load",
        "open(), path.join, send_file, os.path with request-derived values",
        "hashlib.md5/sha1 for security, random.random for tokens, AES.MODE_ECB, static IV",
        "raw request.body / **kwargs / setattr onto ORM models",
        "signature or HMAC checks removed or made optional",
    ],
)

EXPOSURE_SCAN = ScanDefinition(
    key=SCAN_EXPOSURE,
    title="Exposure",
    question="Does this change newly reveal secrets, sensitive information, or attack surface to parties that should not see it?",
    triage_hint=(
        "The change adds or modifies endpoints/routes, logging, error handling, HTTP responses or headers, "
        "client-rendered output, configuration or environment handling, CI/deploy manifests, infra definitions, "
        "third-party integrations, or introduces literal credentials/keys/tokens."
    ),
    categories=[
        "hardcoded_secret", "secret_in_logs", "sensitive_data_in_logs", "sensitive_data_in_response",
        "verbose_error_or_stack_trace_exposure", "debug_endpoint_or_mode_enabled", "information_disclosure",
        "new_unauthenticated_surface", "xss_reflected", "xss_stored", "xss_dom", "html_or_header_injection",
        "permissive_cors", "missing_security_header_with_impact", "insecure_transport",
        "public_cloud_resource_or_bucket", "secret_in_url_or_query", "metadata_or_internal_service_exposure",
        "dependency_or_supply_chain_exposure", "token_or_session_leak_to_third_party", "secret_in_history",
    ],
    in_scope=[
        "Literal secrets: API keys, passwords, private keys, tokens, connection strings, webhook secrets - in code, config, tests, fixtures, CI files, Dockerfiles, or comments.",
        "Sensitive values reaching logs, metrics, traces, crash reports, or analytics (auth headers, cookies, bodies containing PII/credentials).",
        "HTTP responses or error handlers that return more than intended: stack traces, internal paths, SQL, full objects with hidden fields, other users' data in list/detail endpoints.",
        "New or widened attack surface: new routes, RPC methods, GraphQL fields, message handlers, admin/debug endpoints, CLI flags, opened ports, relaxed firewall/security-group rules.",
        "Output encoding for browsers and other consumers: reflected/stored/DOM XSS, unsafe innerHTML/dangerouslySetInnerHTML, template autoescape disabled, header/CRLF injection.",
        "Cross-origin and transport posture: wildcard or reflected CORS with credentials, cookies without Secure/HttpOnly/SameSite where it matters, TLS verification disabled, plaintext endpoints for sensitive traffic.",
        "Infrastructure exposure: public buckets, 0.0.0.0/0 ingress, publicly accessible databases, metadata-service reachability, overly broad IAM trust policies (the *reachability* aspect).",
        "Supply chain: new dependencies from untrusted sources, unpinned installs from URLs, postinstall scripts, typosquat-looking package names.",
        "Secrets or session tokens sent to third parties (analytics, error trackers, LLM APIs, webhooks) or placed in URLs/query strings/referers.",
    ],
    hand_off={
        SCAN_DATA: "Whether the data is *processed* unsafely (injection, deserialization, crypto) - leave that to the data scan.",
        SCAN_ACCESS: "Whether a permission check is *missing or wrong* on an existing endpoint - leave that to the access scan. Report here only when the exposure itself is new (a brand-new unauthenticated route, a leak in a response).",
    },
    signals=[
        "string literals that look like keys/tokens (AKIA..., sk-..., ghp_..., -----BEGIN ... PRIVATE KEY-----, long base64/hex)",
        "logger.* / print / console.log with headers, tokens, passwords, request bodies, user records",
        "DEBUG=True, debug: true, stack traces in responses, verbose error middleware",
        "new @app.route / router.get / rpc definitions, especially without auth decorators",
        "innerHTML, dangerouslySetInnerHTML, |safe, mark_safe, autoescape false, v-html",
        "Access-Control-Allow-Origin: *, credentials: true, verify=False, rejectUnauthorized: false",
        "acl: public-read, 0.0.0.0/0, publicly_accessible = true",
        "curl | sh, pip install from git+http, npm postinstall",
    ],
)

ACCESS_SCAN = ScanDefinition(
    key=SCAN_ACCESS,
    title="Access control",
    question="Does this change let someone do something, or reach something, they should not be authorized to?",
    triage_hint=(
        "The change touches login/signup/password/MFA/SSO/OAuth flows, sessions or tokens, permission or role checks, "
        "middleware/guards/decorators, tenant or ownership scoping, admin functionality, IAM/RBAC policies, "
        "service-to-service auth, feature flags gating sensitive actions, or object lookups keyed by client-supplied IDs."
    ),
    categories=[
        "authentication_bypass", "broken_authorization", "missing_authorization_check", "insecure_direct_object_reference",
        "privilege_escalation", "tenant_isolation_failure", "session_management_flaw", "jwt_validation_flaw",
        "oauth_or_sso_flaw", "password_or_credential_policy_flaw", "mfa_bypass", "csrf",
        "insecure_default_credentials", "overly_permissive_iam_or_rbac", "service_to_service_auth_flaw",
        "rate_limit_bypass_on_auth", "account_takeover_vector", "trust_boundary_violation",
    ],
    in_scope=[
        "Authentication: bypassable checks, auth made optional, weak or predictable credentials/reset tokens, MFA or step-up skipped, password reset/verification flows that can be hijacked.",
        "Session and token handling: JWT signature/alg/expiry/audience not verified, tokens accepted from wrong sources, sessions not rotated on login or invalidated on logout/password change, long-lived tokens where short ones existed.",
        "Authorization: endpoints, handlers, resolvers, jobs, or message consumers that lost or never had a permission check; role or scope checks that compare the wrong thing; client-supplied role/tenant/owner fields trusted.",
        "Object-level access: lookups by ID without ownership/tenant scoping (IDOR), list endpoints returning other tenants' rows, bulk operations that skip per-item checks.",
        "Privilege escalation: paths from low-privilege to admin actions, self-service role changes, impersonation features, sudo-like helpers, feature flags that gate sensitive actions being flipped.",
        "Cross-site request forgery on state-changing routes where the framework protection was disabled or bypassed.",
        "Machine identity: service accounts, IAM roles, Kubernetes RBAC, database grants, or cloud policies widened beyond need (the *permission* aspect); mutual TLS or API-key checks between services removed.",
        "Trust boundaries: internal-only assumptions (localhost, private network, 'trusted' header like X-Forwarded-For or X-User-Id) used as an auth decision.",
    ],
    hand_off={
        SCAN_DATA: "Injection, deserialization, and crypto-of-data bugs even when they occur in auth code - leave those to the data scan (but do report crypto flaws that make a *token forgeable*).",
        SCAN_EXPOSURE: "Leaking of secrets or data in logs/responses and brand-new public surface - leave those to the exposure scan.",
    },
    signals=[
        "removed or commented-out @login_required, @require_permission, authorize(), ensure_owner, tenant_id filters",
        "if user.is_admin or ... with wrong precedence; permission check after the action; early return before the check",
        "Model.objects.get(id=request_id) with no owner/tenant condition",
        "jwt.decode(..., verify=False / algorithms=['none'] / options={'verify_signature': False})",
        "role/tenant/user_id read from request body, query, or headers",
        "csrf_exempt, SameSite=None, CSRF middleware removed",
        "iam policy Action: '*' or Resource: '*', ClusterRole with wildcards, GRANT ALL",
        "trusting X-Forwarded-*, X-Real-IP, X-User-*, or 'internal' flags for auth decisions",
    ],
)

SCAN_DEFINITIONS: Dict[str, ScanDefinition] = {
    DATA_SCAN.key: DATA_SCAN,
    EXPOSURE_SCAN.key: EXPOSURE_SCAN,
    ACCESS_SCAN.key: ACCESS_SCAN,
}

SCAN_ORDER = [SCAN_DATA, SCAN_EXPOSURE, SCAN_ACCESS]


def get_scan(key: str) -> ScanDefinition:
    try:
        return SCAN_DEFINITIONS[key]
    except KeyError as e:
        raise ValueError(f"Unknown scan '{key}'. Valid scans: {', '.join(SCAN_ORDER)}") from e


# Shared finding schema used by every scan (and enforced by the API when using the API backend).
FINDING_SCHEMA: Dict = {
    "type": "object",
    "properties": {
        "file": {"type": "string", "description": "Repository-relative path of the file containing the issue."},
        "line": {"type": "integer", "description": "1-indexed line number on the post-change side of the diff."},
        "severity": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "category": {"type": "string", "description": "Short snake_case vulnerability class."},
        "title": {"type": "string", "description": "One-line summary of the issue."},
        "description": {"type": "string", "description": "What is wrong and why it is exploitable, referencing the specific code."},
        "exploit_scenario": {"type": "string", "description": "Concrete attacker steps and the resulting impact."},
        "recommendation": {"type": "string", "description": "Specific fix."},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "introduced_by_change": {"type": "boolean", "description": "True if the vulnerability is newly introduced or materially worsened by this diff."},
    },
    "required": ["file", "line", "severity", "category", "title", "description", "exploit_scenario", "recommendation", "confidence", "introduced_by_change"],
    "additionalProperties": False,
}

CANDIDATE_VERDICT_SCHEMA: Dict = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "description": "The candidate id exactly as given (e.g. semgrep-2)."},
        "verdict": {"type": "string", "enum": ["confirmed", "dismissed", "unsure"]},
        "reason": {"type": "string", "description": "One sentence: why it is (or is not) exploitable here."},
    },
    "required": ["id", "verdict", "reason"],
    "additionalProperties": False,
}

SCAN_RESULT_SCHEMA: Dict = {
    "type": "object",
    "properties": {
        "findings": {"type": "array", "items": FINDING_SCHEMA},
        "candidate_verdicts": {
            "type": "array",
            "items": CANDIDATE_VERDICT_SCHEMA,
            "description": "One verdict per scanner candidate you were given. Empty when there were none.",
        },
        "reviewed_files": {"type": "array", "items": {"type": "string"}},
        "notes": {"type": "string", "description": "Brief notes on what was checked and any areas that could not be fully assessed."},
    },
    "required": ["findings", "candidate_verdicts", "reviewed_files", "notes"],
    "additionalProperties": False,
}

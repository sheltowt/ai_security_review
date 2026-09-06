# The three scans

Each scan answers exactly one question about a change. The boundaries are deliberate: they keep the
same bug from being reported three times and they give the triage model crisp criteria for deciding
which scans to run. The authoritative definitions live in `ai_security_review/scans.py`; this page is
the human-readable version.

| Scan | Question | Typical triggers in a diff |
|---|---|---|
| **Data** | Is data handled safely? | queries, shell/process calls, deserialisation, file paths, crypto, PII storage, webhooks |
| **Exposure** | What does this reveal? | secrets, logging, error handlers, new routes, browser output, CORS/TLS, infra manifests, dependencies |
| **Access** | Who is allowed to do it? | login/session/JWT code, permission checks, tenant scoping, admin features, IAM/RBAC, CSRF |

## Data handling

*Does this change let untrusted or sensitive data be processed, stored, or transformed unsafely?*

In scope:

- Untrusted input reaching interpreters: SQL/NoSQL, shell, eval/exec, templates, LDAP/XPath, regex built from input.
- Deserialising attacker-controlled bytes (pickle, YAML load, Java/PHP object streams).
- Path construction from input for reads, writes, includes, archive extraction, uploads.
- Cryptographic misuse: deprecated algorithms, ECB, static IVs/nonces/salts, non-CSPRNG for security values, homegrown crypto.
- Sensitive data written to storage, caches, queues, or third parties without the protection the codebase applies elsewhere.
- Integrity: unsigned or unverified data trusted for decisions, client-tampered prices or quantities.
- Mass assignment, unsafe file upload handling, numeric or type-coercion edge cases with security impact.

Hands off to: **Exposure** for whether data is *revealed*; **Access** for whether the caller was *allowed* to act.

## Exposure

*Does this change newly reveal secrets, sensitive information, or attack surface to parties that should not see it?*

In scope:

- Literal secrets in code, config, tests, fixtures, CI files, Dockerfiles, or comments.
- Sensitive values in logs, metrics, traces, crash reports, analytics.
- Responses and error handlers that return too much: stack traces, internal paths, hidden fields, other users' data.
- New or widened attack surface: routes, RPC methods, GraphQL fields, message handlers, admin/debug endpoints, opened ports, relaxed firewall rules.
- Output encoding for browsers: reflected/stored/DOM XSS, unsafe innerHTML, autoescape disabled, header injection.
- CORS and transport posture: wildcard or reflected origins with credentials, cookies without flags where it matters, TLS verification disabled.
- Infrastructure reachability: public buckets, open ingress, publicly accessible databases, metadata-service exposure.
- Supply chain: unpinned installs from URLs, postinstall scripts, typosquat-looking names.
- Secrets or session tokens sent to third parties or placed in URLs.

Hands off to: **Data** for unsafe *processing*; **Access** for a *missing or wrong* permission check on an existing endpoint.

## Access control

*Does this change let someone do something, or reach something, they should not be authorised to?*

In scope:

- Authentication: bypassable or optional checks, weak reset tokens, MFA or step-up skipped, hijackable reset or verification flows.
- Sessions and tokens: JWT signature/alg/expiry/audience not verified, tokens accepted from wrong sources, sessions not rotated or invalidated.
- Authorization: handlers, resolvers, jobs, or consumers missing a permission check; role or scope checks comparing the wrong thing; client-supplied role/tenant/owner fields trusted.
- Object-level access: lookups by ID without ownership or tenant scoping, list endpoints leaking other tenants' rows, bulk operations skipping per-item checks.
- Privilege escalation, impersonation, feature flags gating sensitive actions.
- CSRF protection disabled on state-changing routes.
- Machine identity: IAM roles, Kubernetes RBAC, database grants widened beyond need; service-to-service auth removed.
- Trust boundaries: localhost, private-network, or forwarded-header assumptions used as an auth decision.

Hands off to: **Data** for injection, deserialisation, and crypto-of-data bugs (except crypto flaws that make a token forgeable); **Exposure** for leaks and brand-new public surface.

## Global exclusions

No scan reports: denial of service, resource exhaustion, missing rate limiting, ReDoS, style or test-coverage gaps,
theoretical issues without a realistic attacker path, pre-existing problems the change does not touch, findings in
documentation files, memory-safety bugs in memory-safe languages, or open redirects without a chained impact.

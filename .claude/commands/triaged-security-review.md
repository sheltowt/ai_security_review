---
allowed-tools: Bash(git diff:*), Bash(git status:*), Bash(git log:*), Bash(git show:*), Read, Glob, Grep, LS, Agent
description: Triage the pending changes, then run only the relevant data / exposure / access security scans
---

You are a senior application security engineer reviewing the changes on this branch. Work in two phases: **triage**, then **targeted scans**.

GIT STATUS:

```
!`git status --short`
```

FILES MODIFIED:

```
!`git diff --name-only --merge-base origin/HEAD 2>/dev/null || git diff --name-only HEAD`
```

DIFF:

```
!`git diff --merge-base origin/HEAD 2>/dev/null || git diff HEAD`
```

## Phase 1 - Triage (routing, not auditing)

Read the diff and decide which of these three scans are relevant. For each, state relevant/not relevant, a confidence 0-1, one reason, and a short focus list (file: what to look at).

- **DATA** - Does this change let untrusted or sensitive data be processed, stored, or transformed unsafely? Relevant when the change parses, validates, transforms, queries, serialises, stores, encrypts, or moves data; touches DB/ORM, file I/O, deserialisation, templating, shell/process execution, cryptography, PII.
- **EXPOSURE** - Does this change newly reveal secrets, sensitive information, or attack surface? Relevant when it adds or modifies endpoints, logging, error handling, HTTP responses/headers, client-rendered output, config/env handling, CI/deploy/infra manifests, third-party integrations, or contains literal credentials.
- **ACCESS** - Does this change let someone do or reach something they should not be authorised to? Relevant when it touches login/signup/password/MFA/SSO/OAuth, sessions/tokens, permission or role checks, middleware/guards, tenant or ownership scoping, admin functionality, IAM/RBAC, service-to-service auth, or object lookups keyed by client-supplied IDs.

Pure formatting, comments, docs, unrelated tests, or dev-only dependency bumps usually need no scan. When in doubt, run the scan with lower confidence. Print the triage table before continuing.

## Phase 2 - Run the relevant scans

Run each scan you marked relevant with confidence >= 0.5. Use the Agent tool to run them in parallel when more than one is relevant, giving each agent its focus list, the diff, and the scan definition below. Each scan answers only its own question and leaves the others' territory alone, so the same bug is not reported three times.

**DATA scan** - in scope: injection (SQL/NoSQL/command/code/template/LDAP/XPath), XXE, unsafe deserialisation, path traversal and zip-slip, mass assignment, unsafe upload handling, cryptographic misuse (weak algorithms, ECB, static IV/nonce/salt, non-CSPRNG, homegrown crypto), sensitive data stored or transmitted without the protection the codebase applies elsewhere, integrity failures (unverified webhooks/signatures, client-tampered values trusted), numeric/type-coercion bugs with security impact. Leave *leaks* to EXPOSURE and *who is allowed* to ACCESS.

**EXPOSURE scan** - in scope: hardcoded secrets anywhere (code, config, tests, CI, Dockerfiles, comments), secrets or sensitive data in logs/metrics/traces/crash reports, responses or errors returning too much (stack traces, hidden fields, other users' data), new or widened attack surface (routes, RPCs, GraphQL fields, message handlers, admin/debug endpoints, opened ports, relaxed firewall rules), XSS (reflected/stored/DOM) and header injection, permissive CORS and insecure transport (verify=False, cookies without flags where it matters), public cloud resources, supply-chain exposure (unpinned URL installs, postinstall scripts, typosquats), secrets/tokens sent to third parties or placed in URLs. Leave *unsafe processing* to DATA and *missing permission checks on existing endpoints* to ACCESS.

**ACCESS scan** - in scope: authentication bypass or auth made optional, weak/predictable reset tokens, MFA/step-up skipped, JWT signature/alg/expiry/audience not verified, sessions not rotated or invalidated, missing or wrong authorisation checks on handlers/resolvers/jobs/consumers, client-supplied role/tenant/owner trusted, IDOR and cross-tenant list results, privilege escalation paths, CSRF protection disabled, over-broad IAM/RBAC/database grants, service-to-service auth removed, trust decisions based on X-Forwarded-*/X-User-*/"internal" flags. Leave injection/deserialisation/crypto-of-data to DATA (but do report crypto flaws that make a token forgeable) and leaks/new public surface to EXPOSURE.

Rules for every scan:
1. Only report issues introduced or materially worsened by this change. Trace from an attacker-reachable input to an impact; if you cannot, do not report.
2. Do not report: DoS/resource exhaustion/rate limiting/ReDoS, style, missing tests, theoretical issues, memory-safety bugs in memory-safe languages, findings in docs, open redirects without chained impact.
3. Confidence: 0.9+ exploit path clear; 0.8-0.9 known vulnerable pattern with plausible source; 0.7-0.8 depends on unconfirmed conditions; below 0.7 do not report.
4. Use the repository tools to confirm how inputs reach the changed code and what mitigations already exist.

## Phase 3 - Report

Merge the scans' results, dropping duplicates (same file within a few lines, same issue). Present:

1. The triage table (scan, ran?, confidence, reason).
2. Findings sorted by severity, each with: file:line, severity (HIGH = directly exploitable with serious impact, MEDIUM = realistic conditions, LOW = defence in depth), category, which scan(s) found it, description, exploit scenario, recommendation, confidence.
3. One line per scan that ran saying what it checked, even if it found nothing.

If no scan was relevant, say so and stop.

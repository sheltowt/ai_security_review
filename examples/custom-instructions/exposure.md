# Project-specific exposure notes

- Structured logging is done through `app/logging.py`; it already redacts `authorization`, `cookie`, and `password`
  keys. Logging a raw `request.headers` dict bypasses that and is a finding.
- Everything under `app/admin/` is only reachable behind the internal load balancer, but treat new unauthenticated
  routes there as MEDIUM rather than ignoring them.
- Test fixtures under `tests/fixtures/` may contain fake keys prefixed `test_`; do not report those.

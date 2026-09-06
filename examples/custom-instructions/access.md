# Project-specific access-control notes

- Tenancy is keyed by `org_id`. Every query touching `Document`, `Invoice`, or `Member` must filter by the
  caller's `org_id`; the helper is `scoped_query(model, user)`. A lookup by primary key without it is an IDOR.
- Route protection uses the `@require_role("admin"|"member"|"viewer")` decorator from `app/auth/decorators.py`.
  Handlers without it are anonymous; new anonymous handlers that mutate state are HIGH.
- Service-to-service calls use mutual TLS; API keys in `X-Internal-Key` are legacy and being removed, so do not
  flag their absence.

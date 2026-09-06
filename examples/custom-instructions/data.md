# Project-specific data-handling notes

- All database access goes through `app/db/repo.py`; functions there use parameter binding. Raw `execute(f"...")`
  anywhere else is a finding.
- `app/util/sanitize.py::clean_path()` is the approved path sanitiser for uploads; treat paths passed through it as safe.
- Webhooks from Stripe are verified in `app/webhooks/stripe.py` via `stripe.Webhook.construct_event`; any new webhook
  route that skips an equivalent signature check is a HIGH finding.
- Do not report use of MD5 in `app/cache/keys.py`; it is only used for cache-key derivation.

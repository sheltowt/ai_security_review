# Triage guidance for this project

- Treat any change under `billing/`, `payments/`, or `auth/` as high risk and run all three scans.
- Changes limited to `docs/`, `*.md`, `frontend/storybook/`, or `scripts/dev/` need no scans.
- Infrastructure lives in `infra/terraform/`; changes there usually need the exposure and access scans.

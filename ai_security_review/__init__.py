"""Triage-driven AI security review.

A model first triages a code diff, then targeted scans run only for the
security areas the triage flagged as relevant:

- ``data``     - how untrusted or sensitive data is handled
- ``exposure`` - what the change newly exposes (secrets, surfaces, leaks)
- ``access``   - who can do what (authn, authz, tenancy, privilege)
"""

__version__ = "0.1.0"

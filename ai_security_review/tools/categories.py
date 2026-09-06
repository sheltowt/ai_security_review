"""Map scanner output onto the review's finding categories and the scan that owns each category.

Scanners describe hits with CWE identifiers. Translating them into the same snake_case categories the
model scans use lets the dedupe stage merge a Semgrep hit with the model's write-up of the same line,
and tells the pipeline which scan should verify a candidate.
"""

import re
from typing import Dict, Optional

from ai_security_review.constants import SCAN_DATA, SCAN_EXPOSURE
from ai_security_review.scans import SCAN_DEFINITIONS

# CWE number -> review category. Kept to CWEs that map cleanly; anything else falls back to a generic
# category owned by the data scan (most SAST rules concern untrusted input reaching a sink).
CWE_TO_CATEGORY: Dict[int, str] = {
    # data
    77: "command_injection", 78: "command_injection",
    89: "sql_injection", 943: "nosql_injection",
    94: "code_injection", 95: "code_injection", 96: "code_injection", 470: "code_injection",
    917: "template_injection", 1336: "template_injection",
    90: "ldap_or_xpath_injection", 643: "ldap_or_xpath_injection",
    611: "xxe", 827: "xxe",
    502: "unsafe_deserialization",
    22: "path_traversal", 23: "path_traversal", 36: "path_traversal",
    20: "missing_input_validation_with_impact",
    704: "type_confusion_or_coercion",
    326: "weak_cryptography", 327: "weak_cryptography", 328: "weak_cryptography", 780: "weak_cryptography",
    916: "weak_cryptography", 757: "weak_cryptography",
    329: "improper_key_or_iv_handling", 1204: "improper_key_or_iv_handling",
    330: "insecure_randomness", 338: "insecure_randomness",
    312: "sensitive_data_at_rest_unprotected",
    311: "sensitive_data_in_transit_unprotected", 319: "sensitive_data_in_transit_unprotected",
    345: "data_integrity_or_tampering",
    915: "mass_assignment",
    434: "unsafe_file_upload_handling",
    918: "server_side_request_forgery",
    1321: "prototype_pollution",
    # exposure
    259: "hardcoded_secret", 321: "hardcoded_secret", 798: "hardcoded_secret",
    532: "sensitive_data_in_logs",
    209: "verbose_error_or_stack_trace_exposure",
    489: "debug_endpoint_or_mode_enabled",
    200: "information_disclosure", 215: "information_disclosure",
    79: "xss_reflected", 80: "xss_reflected", 116: "xss_reflected",
    93: "html_or_header_injection", 113: "html_or_header_injection",
    346: "permissive_cors", 942: "permissive_cors",
    614: "missing_security_header_with_impact", 1004: "missing_security_header_with_impact", 1021: "missing_security_header_with_impact",
    295: "insecure_transport", 297: "insecure_transport",
    494: "dependency_or_supply_chain_exposure", 829: "dependency_or_supply_chain_exposure", 1104: "dependency_or_supply_chain_exposure",
    601: "open_redirect",
    # access
    287: "authentication_bypass", 288: "authentication_bypass", 306: "authentication_bypass",
    284: "broken_authorization", 285: "broken_authorization", 863: "broken_authorization",
    862: "missing_authorization_check",
    639: "insecure_direct_object_reference",
    250: "privilege_escalation", 269: "privilege_escalation",
    384: "session_management_flaw", 613: "session_management_flaw",
    347: "jwt_validation_flaw",
    352: "csrf", 1275: "csrf",
    1392: "insecure_default_credentials",
}

# CWEs whose findings the review never reports (see HardExclusionRules and GLOBAL_EXCLUSIONS).
SUPPRESSED_CWES = {400, 770, 1333, 835, 401, 772}

# Categories that are not in any ScanDefinition but still have an obvious owner.
_EXTRA_OWNERS: Dict[str, str] = {
    "server_side_request_forgery": SCAN_DATA,
    "prototype_pollution": SCAN_DATA,
    "open_redirect": SCAN_EXPOSURE,
    "secret_in_history": SCAN_EXPOSURE,
    "security_issue": SCAN_DATA,
}

_CWE_NUMBER = re.compile(r"CWE-(\d+)", re.I)


def cwe_numbers(value) -> list:
    """Extract CWE numbers from a string, a list of strings, or None."""
    if not value:
        return []
    items = value if isinstance(value, (list, tuple)) else [value]
    out = []
    for item in items:
        for m in _CWE_NUMBER.finditer(str(item)):
            out.append(int(m.group(1)))
    return out


def category_for_cwes(cwes) -> Optional[str]:
    """First mapped category for a list of CWE numbers, or None."""
    for n in cwe_numbers(cwes):
        cat = CWE_TO_CATEGORY.get(n)
        if cat:
            return cat
    return None


def is_suppressed(cwes) -> bool:
    numbers = cwe_numbers(cwes)
    return bool(numbers) and all(n in SUPPRESSED_CWES for n in numbers)


def owner_scan(category: str) -> str:
    """The scan whose question a category belongs to. Defaults to the data scan."""
    for scan in SCAN_DEFINITIONS.values():
        if category in scan.categories:
            return scan.key
    return _EXTRA_OWNERS.get(category, SCAN_DATA)


__all__ = ["CWE_TO_CATEGORY", "SUPPRESSED_CWES", "category_for_cwes", "cwe_numbers", "is_suppressed", "owner_scan"]

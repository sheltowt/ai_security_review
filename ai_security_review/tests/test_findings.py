from ai_security_review.diff import ExclusionRules, build_bundle
from ai_security_review.findings import HardExclusionRules, merge_duplicates, normalize_finding, process_findings


def test_normalize_defaults():
    f = normalize_finding({"file": "./a/b.py", "line": "7", "severity": "critical", "confidence": "0.85", "scan": "data"})
    assert f["file"] == "a/b.py"
    assert f["line"] == 7
    assert f["severity"] == "MEDIUM"          # unknown severity falls back
    assert f["confidence"] == 0.85
    assert f["category"] == "security_issue"
    assert f["scans"] == ["data"]
    assert f["title"]                         # derived from category


def test_hard_exclusions():
    assert HardExclusionRules.exclusion_reason({"file": "docs/x.md", "description": "sql injection"})
    assert HardExclusionRules.exclusion_reason({"file": "a.py", "description": "Missing rate limiting on login"})
    assert HardExclusionRules.exclusion_reason({"file": "a.py", "description": "This allows denial of service"})
    assert HardExclusionRules.exclusion_reason({"file": "a.py", "description": "buffer overflow in parser"})
    assert not HardExclusionRules.exclusion_reason({"file": "a.c", "description": "buffer overflow in parser"})
    assert not HardExclusionRules.exclusion_reason({"file": "a.py", "description": "SQL injection via q param"})
    # open redirect chained into token theft survives
    assert not HardExclusionRules.exclusion_reason({"file": "a.py", "description": "open redirect leaks the oauth code to attacker"})
    assert HardExclusionRules.exclusion_reason({"file": "a.py", "description": "open redirect to arbitrary site"})


def test_merge_duplicates_across_scans(helpers):
    a = normalize_finding({**helpers["finding"](), "scan": "data"})
    b = normalize_finding({**helpers["finding"](line=16, category="injection", title="SQL injection via q", confidence=0.8), "scan": "exposure"})
    merged, n = merge_duplicates([a, b])
    assert n == 1 and len(merged) == 1
    assert merged[0]["scans"] == ["data", "exposure"]
    assert merged[0]["confidence"] == 0.95


def test_merge_keeps_stronger_writeup(helpers):
    weak = normalize_finding({**helpers["finding"](severity="MEDIUM", confidence=0.7), "scan": "exposure"})
    strong = normalize_finding({**helpers["finding"](severity="HIGH", confidence=0.9, description="strong"), "scan": "data"})
    merged, _ = merge_duplicates([weak, strong])
    assert merged[0]["severity"] == "HIGH" and merged[0]["description"] == "strong"
    assert merged[0]["scans"] == ["data", "exposure"]


def test_distinct_findings_not_merged(helpers):
    a = normalize_finding({**helpers["finding"](), "scan": "data"})
    b = normalize_finding({**helpers["finding"](line=16, category="secret_in_logs", title="Authorization header logged", description="Bearer token written to logs"), "scan": "exposure"})
    merged, n = merge_duplicates([a, b])
    assert n == 0 and len(merged) == 2


def test_process_findings_pipeline(sample_diff, helpers):
    bundle = build_bundle(sample_diff)
    raw = [
        {**helpers["finding"](), "scan": "data"},
        {**helpers["finding"](confidence=0.5, line=40, category="weak"), "scan": "data"},                       # low confidence
        {**helpers["finding"](file="README.md", category="xss"), "scan": "exposure"},                           # docs
        {**helpers["finding"](file="other/untouched.py", category="idor"), "scan": "access"},                   # not in diff
        {**helpers["finding"](file="vendor/lib.js", category="code_injection", line=2), "scan": "data"},        # excluded dir
        {**helpers["finding"](severity="LOW", line=16, category="secret_in_logs", title="Token logged", description="auth header logged"), "scan": "exposure"},
    ]
    kept, summary = process_findings(raw, bundle, ExclusionRules(["vendor"]))
    assert [f["category"] for f in kept] == ["sql_injection", "secret_in_logs"]
    assert kept[0]["severity"] == "HIGH"
    assert summary.total == 6 and summary.kept == 2
    assert summary.excluded_low_confidence == 1
    assert summary.excluded_by_rule == 1
    assert summary.excluded_not_in_diff == 1
    assert summary.excluded_directory == 1
    assert len(summary.excluded_details) == 4


def test_diff_prefix_only_stripped_when_it_matches(sample_diff, helpers):
    bundle = build_bundle(sample_diff)
    raw = [{**helpers["finding"](file="b/app/api/users.py"), "scan": "data"}]
    kept, _ = process_findings(raw, bundle)
    assert kept[0]["file"] == "app/api/users.py"
    f = normalize_finding({"file": "a/real_dir.py"})
    assert f["file"] == "a/real_dir.py"

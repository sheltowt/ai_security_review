from ai_security_review.triage import forced_triage, run_triage, select_scans


def test_select_scans_threshold():
    scans = {
        "data": {"relevant": True, "confidence": 0.9},
        "exposure": {"relevant": True, "confidence": 0.4},
        "access": {"relevant": False, "confidence": 0.99},
    }
    assert select_scans(scans, 0.5) == ["data"]
    assert select_scans(scans, 0.3) == ["data", "exposure"]


def test_forced_triage():
    t = forced_triage(["access", "data"])
    assert t.selected_scans == ["data", "access"]
    assert t.skipped
    assert t.scans["exposure"]["relevant"] is False


def test_run_triage_parses_and_selects(bundle, fake_client_factory, helpers):
    client = fake_client_factory({"triage": helpers["triage_payload"]()})
    t = run_triage(client, bundle, {"repo": "o/r", "number": 1, "title": "t"}, model="claude-opus-5", effort="medium")
    assert t.selected_scans == ["data", "exposure"]
    assert t.risk_level == "high"
    assert client.calls[0]["label"] == "triage"
    assert client.calls[0]["effort"] == "medium"
    assert client.calls[0]["schema"]["required"]


def test_run_triage_tolerates_missing_scan_entries(bundle, fake_client_factory):
    client = fake_client_factory({"triage": {"summary": "x", "change_kind": "docs", "risk_level": "none", "scans": {}, "notes": ""}})
    t = run_triage(client, bundle)
    assert t.selected_scans == []
    assert set(t.scans) == {"data", "exposure", "access"}

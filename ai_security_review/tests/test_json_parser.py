from ai_security_review.json_parser import extract_json_from_text, parse_json_with_fallbacks


def test_direct():
    assert extract_json_from_text('{"a": 1}') == {"a": 1}


def test_fenced():
    assert extract_json_from_text('Here:\n```json\n{"a": [1,2]}\n```\ndone') == {"a": [1, 2]}


def test_embedded_with_braces_in_strings():
    text = 'prefix {"findings": [{"title": "uses {braces} and \\"quotes\\""}]} suffix'
    assert extract_json_from_text(text)["findings"][0]["title"] == 'uses {braces} and "quotes"'


def test_failure():
    ok, err = parse_json_with_fallbacks("no json here", "ctx")
    assert not ok and "ctx" in err["error"]

import types

import anthropic
import httpx2 as httpx
import pytest

from ai_security_review.claude_client import ClaudeCallError, ClaudeClient


class _Block:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _Message:
    def __init__(self, text, stop_reason="end_turn", model="claude-opus-5"):
        self.content = [_Block(text)]
        self.stop_reason = stop_reason
        self.stop_details = None
        self.model = model
        self.usage = types.SimpleNamespace(input_tokens=10, output_tokens=5)
        self._request_id = "req_1"


class _Stream:
    def __init__(self, message):
        self.message = message

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_final_message(self):
        return self.message


class _FakeMessages:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def stream(self, **params):
        self.calls.append(params)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return _Stream(outcome)


def _client(outcomes, **kw):
    fake = types.SimpleNamespace(messages=_FakeMessages(outcomes))
    return ClaudeClient(client=fake, **kw), fake.messages


def _status_error(cls, status):
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    resp = httpx.Response(status, request=req, headers={"retry-after": "0"})
    return cls("err", response=resp, body=None)


def test_structured_call_success_and_request_shape():
    client, messages = _client([_Message('{"ok": true}')])
    r = client.structured_call(model="claude-opus-5", system="s", user="u", schema={"type": "object"}, max_tokens=100, effort="low", label="t")
    assert r.data == {"ok": True}
    assert client.total_input_tokens == 10
    params = messages.calls[0]
    assert params["output_config"] == {"effort": "low", "format": {"type": "json_schema", "schema": {"type": "object"}}}
    assert params["extra_body"] == {"fallbacks": "default"}
    assert "server-side-fallback" in params["extra_headers"]["anthropic-beta"]


def test_fallback_can_be_disabled():
    client, messages = _client([_Message("{}")], enable_refusal_fallback=False)
    client.structured_call(model="m", system="s", user="u", schema={}, max_tokens=10)
    assert "extra_body" not in messages.calls[0]


def test_refusal_is_not_retried():
    client, messages = _client([_Message("", stop_reason="refusal")])
    with pytest.raises(ClaudeCallError, match="refused"):
        client.structured_call(model="m", system="s", user="u", schema={}, max_tokens=10)
    assert len(messages.calls) == 1


def test_retry_on_server_error_then_success(monkeypatch):
    monkeypatch.setattr("ai_security_review.claude_client.time.sleep", lambda _: None)
    client, messages = _client([_status_error(anthropic.InternalServerError, 500), _Message('{"a":1}')])
    assert client.structured_call(model="m", system="s", user="u", schema={}, max_tokens=10).data == {"a": 1}
    assert len(messages.calls) == 2


def test_rate_limit_retries(monkeypatch):
    monkeypatch.setattr("ai_security_review.claude_client.time.sleep", lambda _: None)
    client, messages = _client([_status_error(anthropic.RateLimitError, 429), _Message("{}")])
    client.structured_call(model="m", system="s", user="u", schema={}, max_tokens=10)
    assert len(messages.calls) == 2


def test_bad_request_not_retried():
    client, messages = _client([_status_error(anthropic.BadRequestError, 400)])
    with pytest.raises(ClaudeCallError, match="BadRequestError"):
        client.structured_call(model="m", system="s", user="u", schema={}, max_tokens=10)
    assert len(messages.calls) == 1


def test_unparseable_output_retried_once(monkeypatch):
    client, messages = _client([_Message("not json"), _Message("still not json")])
    with pytest.raises(ClaudeCallError, match="could not parse"):
        client.structured_call(model="m", system="s", user="u", schema={}, max_tokens=10)
    assert len(messages.calls) == 2


def test_connection_error_retried(monkeypatch):
    monkeypatch.setattr("ai_security_review.claude_client.time.sleep", lambda _: None)
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    client, messages = _client([anthropic.APIConnectionError(request=req), _Message("{}")])
    client.structured_call(model="m", system="s", user="u", schema={}, max_tokens=10)
    assert len(messages.calls) == 2


def test_max_tokens_truncation_retried_then_fails(monkeypatch):
    client, messages = _client([_Message("{", stop_reason="max_tokens"), _Message("{", stop_reason="max_tokens")])
    with pytest.raises(ClaudeCallError, match="max_tokens"):
        client.structured_call(model="m", system="s", user="u", schema={}, max_tokens=10)
    assert len(messages.calls) == 2


def test_exhausted_retries_raise(monkeypatch):
    monkeypatch.setattr("ai_security_review.claude_client.time.sleep", lambda _: None)
    errors = [_status_error(anthropic.InternalServerError, 503) for _ in range(3)]
    client, _ = _client(errors, max_retries=3)
    with pytest.raises(ClaudeCallError, match="failed after 3 attempts"):
        client.structured_call(model="m", system="s", user="u", schema={}, max_tokens=10)


def test_retry_after_header_parsing():
    from ai_security_review.claude_client import _retry_after_seconds

    def err(headers):
        req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        return anthropic.RateLimitError("x", response=httpx.Response(429, request=req, headers=headers), body=None)

    assert _retry_after_seconds(err({"retry-after": "7"}), default=30) == 7
    assert _retry_after_seconds(err({"retry-after": "9999"}), default=30) == 120   # capped
    assert _retry_after_seconds(err({"retry-after": "soon"}), default=30) == 30    # unparseable
    assert _retry_after_seconds(err({}), default=30) == 30                         # absent
    assert _retry_after_seconds(RuntimeError("no response attr"), default=4) == 4

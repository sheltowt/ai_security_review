"""Thin wrapper over the Anthropic Messages API for structured JSON calls."""

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import anthropic

from ai_security_review.constants import (
    API_MAX_RETRIES,
    API_TIMEOUT_SECONDS,
    ENABLE_REFUSAL_FALLBACK,
    REFUSAL_FALLBACK_BETA,
)
from ai_security_review.json_parser import parse_json_with_fallbacks
from ai_security_review.logger import get_logger

logger = get_logger(__name__)


class ClaudeCallError(RuntimeError):
    """Raised when a model call fails after retries or is refused."""


@dataclass
class StructuredResponse:
    data: Any
    model: str
    input_tokens: int
    output_tokens: int
    request_id: Optional[str]
    raw_text: str


class ClaudeClient:
    """Structured-output calls with retry, refusal handling, and usage tracking."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout_seconds: int = API_TIMEOUT_SECONDS,
        max_retries: int = API_MAX_RETRIES,
        enable_refusal_fallback: bool = ENABLE_REFUSAL_FALLBACK,
        client: Optional[anthropic.Anthropic] = None,
    ):
        # A zero-arg Anthropic() resolves ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN / an `ant auth login` profile.
        self.client = client or anthropic.Anthropic(api_key=api_key, timeout=timeout_seconds, max_retries=0)
        self.max_retries = max_retries
        self.enable_refusal_fallback = enable_refusal_fallback
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def structured_call(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema: Dict[str, Any],
        max_tokens: int,
        effort: str = "high",
        label: str = "call",
    ) -> StructuredResponse:
        """Call the model and return JSON validated against ``schema`` by the API."""
        params: Dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "output_config": {
                "effort": effort,
                "format": {"type": "json_schema", "schema": schema},
            },
        }
        if self.enable_refusal_fallback:
            # Server-side refusal fallback: if a safety classifier declines, the API re-runs
            # the request on Anthropic's recommended substitute model inside the same call.
            params["extra_headers"] = {"anthropic-beta": REFUSAL_FALLBACK_BETA}
            params["extra_body"] = {"fallbacks": "default"}

        last_error: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                started = time.time()
                with self.client.messages.stream(**params) as stream:
                    message = stream.get_final_message()
                elapsed = time.time() - started

                usage = getattr(message, "usage", None)
                in_tok = int(getattr(usage, "input_tokens", 0) or 0)
                out_tok = int(getattr(usage, "output_tokens", 0) or 0)
                self.total_input_tokens += in_tok
                self.total_output_tokens += out_tok
                request_id = getattr(message, "_request_id", None)
                logger.info("%s: %s finished in %.1fs (%d in / %d out tokens, request %s)", label, message.model, elapsed, in_tok, out_tok, request_id)

                if message.stop_reason == "refusal":
                    details = getattr(message, "stop_details", None)
                    category = getattr(details, "category", None) if details else None
                    raise ClaudeCallError(f"{label}: model refused the request (category={category})")
                if message.stop_reason == "max_tokens":
                    raise ClaudeCallError(f"{label}: output truncated at max_tokens={max_tokens}")

                text = "".join(block.text for block in message.content if getattr(block, "type", "") == "text")
                ok, data = parse_json_with_fallbacks(text, label)
                if not ok:
                    raise ClaudeCallError(f"{label}: {data.get('error')}")
                return StructuredResponse(
                    data=data,
                    model=message.model,
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                    request_id=request_id,
                    raw_text=text,
                )

            except (anthropic.BadRequestError, anthropic.AuthenticationError, anthropic.PermissionDeniedError, anthropic.NotFoundError) as e:
                # Not retryable: bad schema, bad key, bad model.
                raise ClaudeCallError(f"{label}: {type(e).__name__}: {getattr(e, 'message', str(e))}") from e
            except anthropic.RateLimitError as e:
                last_error = e
                retry_after = _retry_after_seconds(e, default=15 * attempt)
                logger.warning("%s: rate limited (attempt %d/%d), sleeping %ss", label, attempt, self.max_retries, retry_after)
                time.sleep(retry_after)
            except anthropic.APIStatusError as e:
                last_error = e
                if e.status_code < 500:
                    raise ClaudeCallError(f"{label}: API error {e.status_code}: {getattr(e, 'message', str(e))}") from e
                logger.warning("%s: server error %s (attempt %d/%d)", label, e.status_code, attempt, self.max_retries)
                time.sleep(5 * attempt)
            except anthropic.APIConnectionError as e:
                last_error = e
                logger.warning("%s: connection error (attempt %d/%d): %s", label, attempt, self.max_retries, e)
                time.sleep(5 * attempt)
            except ClaudeCallError as e:
                # Refusal / truncation / unparseable JSON: retry once, then give up.
                last_error = e
                if attempt >= 2 or "refused" in str(e):
                    raise
                logger.warning("%s: %s (retrying)", label, e)

        raise ClaudeCallError(f"{label}: failed after {self.max_retries} attempts: {last_error}") from last_error


def _retry_after_seconds(error: Exception, default: int) -> int:
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None)
    if headers:
        try:
            return max(1, min(120, int(headers.get("retry-after", default))))
        except (TypeError, ValueError):
            pass
    return default


def schema_to_prompt_hint(schema: Dict[str, Any]) -> str:
    """Render a schema as a compact JSON hint for prompts that cannot use output_config."""
    return json.dumps(schema, indent=2)

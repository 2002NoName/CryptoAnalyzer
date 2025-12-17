"""Minimal OpenAI-compatible Chat Completions client.

Uses only the Python standard library so the project stays lightweight.
Works with OpenAI and most OpenAI-compatible endpoints.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import AiConfig


class AiClientError(RuntimeError):
    pass


@dataclass(slots=True)
class OpenAIChatClient:
    config: AiConfig
    timeout_seconds: float = 30.0

    def chat(self, *, system: str, user: str, temperature: float = 0.2) -> str:
        url = self._chat_completions_url(self.config.endpoint)

        payload = {
            "model": self.config.model,
            "temperature": float(temperature),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }

        body = json.dumps(payload).encode("utf-8")
        request = Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}",
            },
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8", "replace")
        except HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace") if hasattr(exc, "read") else str(exc)
            raise AiClientError(f"AI HTTP error: {exc.code} {exc.reason} - {raw}") from exc
        except URLError as exc:
            raise AiClientError(f"AI connection error: {exc}") from exc
        except Exception as exc:
            raise AiClientError(f"AI request failed: {exc}") from exc

        try:
            data: dict[str, Any] = json.loads(raw)
        except Exception as exc:
            raise AiClientError("AI returned invalid JSON") from exc

        # OpenAI Chat Completions response shape
        try:
            return str(data["choices"][0]["message"]["content"])
        except Exception:
            # helpful fallback for non-standard but compatible shapes
            if "error" in data:
                raise AiClientError(f"AI error: {data['error']}")
            raise AiClientError("AI response missing choices/message/content")

    @staticmethod
    def _chat_completions_url(endpoint: str) -> str:
        endpoint = endpoint.strip()
        if not endpoint:
            raise AiClientError("Missing AI endpoint")

        # If a full path is provided, use it.
        lowered = endpoint.lower()
        if lowered.endswith("/v1/chat/completions") or lowered.endswith("/chat/completions"):
            return endpoint

        # If endpoint already ends with /v1, append the rest.
        if lowered.endswith("/v1"):
            return endpoint.rstrip("/") + "/chat/completions"

        # Otherwise assume base URL.
        return endpoint.rstrip("/") + "/v1/chat/completions"

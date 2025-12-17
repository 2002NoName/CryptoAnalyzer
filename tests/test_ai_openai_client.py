import json
import urllib.error

import pytest


class _FakeResponse:
    def __init__(self, status: int, payload: dict):
        self.status = status
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_builds_v1_chat_completions_when_missing(monkeypatch):
    from crypto_analyzer.ai.config import AiConfig
    from crypto_analyzer.ai.openai_client import OpenAIChatClient

    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return _FakeResponse(
            200,
            {"choices": [{"message": {"content": "ok"}}]},
        )

    monkeypatch.setattr("crypto_analyzer.ai.openai_client.urlopen", fake_urlopen)

    client = OpenAIChatClient(AiConfig(api_key="k", endpoint="https://api.example.test", model="4o-mini"))
    out = client.chat(system="sys", user="hi", temperature=0)

    assert out == "ok"
    assert captured["url"] == "https://api.example.test/v1/chat/completions"


def test_keeps_existing_v1_prefix(monkeypatch):
    from crypto_analyzer.ai.config import AiConfig
    from crypto_analyzer.ai.openai_client import OpenAIChatClient

    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return _FakeResponse(
            200,
            {"choices": [{"message": {"content": "ok"}}]},
        )

    monkeypatch.setattr("crypto_analyzer.ai.openai_client.urlopen", fake_urlopen)

    client = OpenAIChatClient(AiConfig(api_key="k", endpoint="https://api.example.test/v1", model="4o-mini"))
    client.chat(system="sys", user="hi", temperature=0)

    assert captured["url"] == "https://api.example.test/v1/chat/completions"


def test_raises_on_http_error(monkeypatch):
    from crypto_analyzer.ai.config import AiConfig
    from crypto_analyzer.ai.openai_client import OpenAIChatClient, AiClientError

    class _Fp:
        def read(self):
            return b"{\"error\":\"nope\"}"

        def close(self):
            return None

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 401, "unauthorized", hdrs=None, fp=_Fp())

    monkeypatch.setattr("crypto_analyzer.ai.openai_client.urlopen", fake_urlopen)

    client = OpenAIChatClient(AiConfig(api_key="k", endpoint="https://api.example.test", model="4o-mini"))

    with pytest.raises(AiClientError):
        client.chat(system="sys", user="hi", temperature=0)

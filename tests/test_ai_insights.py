import json

import pytest


def test_generate_summary_and_suspicious_parses_json(monkeypatch):
    from crypto_analyzer.ai.config import AiConfig
    from crypto_analyzer.ai.insights import AiInsightsService

    service = AiInsightsService(AiConfig(api_key="k", endpoint="https://api.example.test", model="4o-mini"))

    monkeypatch.setattr("crypto_analyzer.ai.insights.build_ai_context", lambda *_args, **_kwargs: {"ok": True})

    class _Client:
        def chat(self, *, system, user, temperature):
            assert "CONTEXT_JSON" in user
            assert "Reply in Polish" in system
            return json.dumps({"summary": "S", "suspicious": "X", "next_steps": "N"})

    service._client = _Client()  # type: ignore[assignment]

    out = service.generate_summary_and_suspicious(object(), ui_locale="pl")
    assert out["summary"] == "S"
    assert out["suspicious"] == "X"
    assert out["next_steps"] == "N"


def test_generate_summary_and_suspicious_fallback_on_bad_json(monkeypatch):
    from crypto_analyzer.ai.config import AiConfig
    from crypto_analyzer.ai.insights import AiInsightsService

    service = AiInsightsService(AiConfig(api_key="k", endpoint="https://api.example.test", model="4o-mini"))

    monkeypatch.setattr("crypto_analyzer.ai.insights.build_ai_context", lambda *_args, **_kwargs: {"ok": True})

    class _Client:
        def chat(self, **_):
            return "not-json"

    service._client = _Client()  # type: ignore[assignment]

    out = service.generate_summary_and_suspicious(object())
    assert out["summary"] == "not-json"
    assert out["suspicious"] == ""
    assert out["next_steps"] == ""


def test_generate_summary_and_suspicious_normalizes_list_outputs(monkeypatch):
    from crypto_analyzer.ai.config import AiConfig
    from crypto_analyzer.ai.insights import AiInsightsService

    service = AiInsightsService(AiConfig(api_key="k", endpoint="https://api.example.test", model="4o-mini"))

    monkeypatch.setattr("crypto_analyzer.ai.insights.build_ai_context", lambda *_args, **_kwargs: {"ok": True})

    class _Client:
        def chat(self, *, system, user, temperature):
            return json.dumps(
                {
                    "summary": ["A", "B"],
                    "suspicious": [
                        {"path": "/a.dat", "reason": "extension:.dat"},
                        "/b: keyword:pass",
                    ],
                    "next_steps": ["N1", "N2"],
                }
            )

    service._client = _Client()  # type: ignore[assignment]

    out = service.generate_summary_and_suspicious(object())
    assert out["summary"] == "- A\n- B"
    assert out["suspicious"] == "- /a.dat — extension:.dat\n- /b: keyword:pass"
    assert out["next_steps"] == "- N1\n- N2"


def test_answer_question_returns_text(monkeypatch):
    from crypto_analyzer.ai.config import AiConfig
    from crypto_analyzer.ai.insights import AiInsightsService

    service = AiInsightsService(AiConfig(api_key="k", endpoint="https://api.example.test", model="4o-mini"))
    monkeypatch.setattr("crypto_analyzer.ai.insights.build_ai_context", lambda *_args, **_kwargs: {"ok": True})

    class _Client:
        def chat(self, **_):
            return "answer"

    service._client = _Client()  # type: ignore[assignment]

    assert service.answer_question(object(), "Q?") == "answer"


def test_answer_question_rejects_empty_question(monkeypatch):
    from crypto_analyzer.ai.config import AiConfig
    from crypto_analyzer.ai.insights import AiInsightsService

    service = AiInsightsService(AiConfig(api_key="k", endpoint="https://api.example.test", model="4o-mini"))

    # Ensure we don't try to build context for empty questions.
    monkeypatch.setattr(
        "crypto_analyzer.ai.insights.build_ai_context",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("should not")),
    )

    with pytest.raises(ValueError):
        service.answer_question(object(), "   ")

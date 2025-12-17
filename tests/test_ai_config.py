import os

import pytest


def test_load_ai_config_missing_returns_none(monkeypatch):
    monkeypatch.setenv("CRYPTOANALYZER_DISABLE_DOTENV", "1")
    monkeypatch.delenv("CRYPTOAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CRYPTOAI_ENDPOINT", raising=False)
    monkeypatch.delenv("OPENAI_ENDPOINT", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    from crypto_analyzer.ai.config import load_ai_config

    assert load_ai_config() is None


def test_load_ai_config_defaults_model(monkeypatch):
    monkeypatch.setenv("CRYPTOANALYZER_DISABLE_DOTENV", "1")
    monkeypatch.setenv("CRYPTOAI_API_KEY", "k")
    monkeypatch.setenv("CRYPTOAI_ENDPOINT", "https://example.test")
    monkeypatch.delenv("CRYPTOAI_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    from crypto_analyzer.ai.config import load_ai_config

    cfg = load_ai_config()
    assert cfg is not None
    assert cfg.model == "4o-mini"


def test_load_ai_config_normalizes_openai_model_alias(monkeypatch):
    monkeypatch.setenv("CRYPTOANALYZER_DISABLE_DOTENV", "1")
    monkeypatch.setenv("CRYPTOAI_API_KEY", "k")
    monkeypatch.setenv("CRYPTOAI_ENDPOINT", "https://api.openai.com")
    monkeypatch.delenv("CRYPTOAI_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    from crypto_analyzer.ai.config import load_ai_config

    cfg = load_ai_config()
    assert cfg is not None
    assert cfg.model == "gpt-4o-mini"


def test_load_ai_config_respects_openai_vars(monkeypatch):
    monkeypatch.setenv("CRYPTOANALYZER_DISABLE_DOTENV", "1")
    monkeypatch.delenv("CRYPTOAI_API_KEY", raising=False)
    monkeypatch.delenv("CRYPTOAI_ENDPOINT", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.example.test/v1")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-x")

    from crypto_analyzer.ai.config import load_ai_config

    cfg = load_ai_config()
    assert cfg is not None
    assert cfg.api_key == "k"
    assert cfg.endpoint == "https://api.example.test/v1"
    assert cfg.model == "gpt-x"

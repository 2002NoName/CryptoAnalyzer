"""Environment-based configuration for AI integration."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class AiConfig:
    api_key: str
    endpoint: str
    model: str


_SUPPORTED_ENV_KEYS = {
    "CRYPTOAI_API_KEY",
    "CRYPTOAI_ENDPOINT",
    "CRYPTOAI_MODEL",
    "OPENAI_API_KEY",
    "OPENAI_ENDPOINT",
    "OPENAI_BASE_URL",
    "OPENAI_MODEL",
}


def _load_dotenv_if_present() -> None:
    """Best-effort .env loader.

    The app primarily uses process environment variables. This loader exists to
    support typical developer workflows on Windows where launching from Explorer
    won't inherit a terminal session's env.

    Rules:
    - Only loads known keys used by this project.
    - Never overwrites variables already present in os.environ.
    - Searches in CWD and (when installed editable) the project root.
    """

    if (os.getenv("CRYPTOANALYZER_DISABLE_DOTENV") or "").strip().lower() in {"1", "true", "yes", "on"}:
        return

    candidates: list[Path] = [Path.cwd() / ".env"]

    try:
        # .../src/crypto_analyzer/ai/config.py -> project root is parents[3]
        project_root = Path(__file__).resolve().parents[3]
        candidates.append(project_root / ".env")
    except Exception:
        pass

    dotenv_path = next((p for p in candidates if p.is_file()), None)
    if dotenv_path is None:
        return

    try:
        for raw_line in dotenv_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key not in _SUPPORTED_ENV_KEYS:
                continue
            if key in os.environ and os.environ[key].strip():
                continue
            value = value.strip().strip('"').strip("'")
            if value:
                os.environ[key] = value
    except Exception:
        # Never block app startup due to dotenv parsing.
        return


def load_ai_config() -> AiConfig | None:
    """Loads AI config from environment.

    Required variables (any one set per field is accepted):
    - API key: `CRYPTOAI_API_KEY` or `OPENAI_API_KEY`
    - Endpoint: `CRYPTOAI_ENDPOINT` or `OPENAI_ENDPOINT` or `OPENAI_BASE_URL`
    - Model: `CRYPTOAI_MODEL` or `OPENAI_MODEL` (default: "4o-mini")

    The feature is considered enabled only when api_key and endpoint are set.
    Model can fall back to the default.
    """

    _load_dotenv_if_present()

    api_key = (os.getenv("CRYPTOAI_API_KEY") or os.getenv("OPENAI_API_KEY") or "").strip()
    endpoint = (
        os.getenv("CRYPTOAI_ENDPOINT")
        or os.getenv("OPENAI_ENDPOINT")
        or os.getenv("OPENAI_BASE_URL")
        or ""
    ).strip()
    model = (os.getenv("CRYPTOAI_MODEL") or os.getenv("OPENAI_MODEL") or "4o-mini").strip()

    if not api_key or not endpoint:
        return None

    model = _normalize_model_for_endpoint(endpoint, model)
    return AiConfig(api_key=api_key, endpoint=endpoint, model=model)


def _normalize_model_for_endpoint(endpoint: str, model: str) -> str:
    """Normalize model ids for known providers.

    The UI/docs historically refer to "4o-mini" as a shorthand.
    OpenAI's public API uses the model id "gpt-4o-mini".

    For OpenAI endpoints we translate the shorthand to the correct id.
    For other OpenAI-compatible endpoints we keep the model unchanged.
    """

    normalized = (model or "").strip() or "4o-mini"
    if normalized != "4o-mini":
        return normalized

    try:
        netloc = urlparse((endpoint or "").strip()).netloc.lower()
    except Exception:
        netloc = ""

    if netloc.endswith("openai.com"):
        return "gpt-4o-mini"
    return normalized

"""High-level AI features: summary, suspicious activity analysis, and Q&A."""

from __future__ import annotations

import json
from typing import Any

from crypto_analyzer.core.models import AnalysisResult

from .config import AiConfig
from .context import build_ai_context
from .openai_client import OpenAIChatClient


class AiInsightsService:
    """Generates post-analysis insights using an OpenAI-compatible endpoint."""

    def __init__(self, config: AiConfig) -> None:
        self._client = OpenAIChatClient(config)

    def generate_summary_and_suspicious(self, result: AnalysisResult, *, ui_locale: str | None = None) -> dict[str, str]:
        context = build_ai_context(result, ui_locale=ui_locale)
        context_json = json.dumps(context, ensure_ascii=False)

        language = _locale_to_language(ui_locale)

        system = (
            "You are a digital forensics assistant. "
            f"Reply in {language}. "
            "You must base your output strictly on the provided JSON context. "
            "If information is missing, say so explicitly. "
            "Keep output concise and structured."
        )

        user = (
            "Given this disk analysis context (JSON), produce a STRICT JSON object with keys:\n"
            "- summary: string (5-10 concise bullet lines)\n"
            "- suspicious: string (bullet lines; reference suspicious_hits when present)\n"
            "- next_steps: string (bullet lines)\n"
            "Rules: output JSON only, no markdown fences, no extra keys. Values MUST be strings (not arrays).\n\n"
            f"CONTEXT_JSON:\n{context_json}"
        )

        text = self._client.chat(system=system, user=user, temperature=0.2)
        try:
            parsed = json.loads(text)
        except Exception:
            # Fallback: display raw text in summary.
            return {"summary": text, "suspicious": "", "next_steps": ""}

        summary = _normalize_bullets(parsed.get("summary", ""))
        suspicious = _normalize_suspicious(parsed.get("suspicious", ""))
        next_steps = _normalize_bullets(parsed.get("next_steps", ""))
        return {"summary": summary, "suspicious": suspicious, "next_steps": next_steps}

    def answer_question(self, result: AnalysisResult, question: str, *, ui_locale: str | None = None) -> str:
        question = (question or "").strip()
        if not question:
            raise ValueError("Question cannot be empty")

        context = build_ai_context(result, ui_locale=ui_locale)
        context_json = json.dumps(context, ensure_ascii=False)

        language = _locale_to_language(ui_locale)

        system = (
            "You are a digital forensics assistant. "
            f"Reply in {language}. "
            "Answer the user's question strictly using the provided JSON context. "
            "If the answer cannot be derived from the context, say what is missing."
        )

        user = "Question: " + question + "\n\nCONTEXT_JSON:\n" + context_json

        return self._client.chat(system=system, user=user, temperature=0.1)


def _normalize_bullets(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value

    if isinstance(value, list):
        lines: list[str] = []
        for item in value:
            if item is None:
                continue
            if isinstance(item, str):
                text = item.strip()
            else:
                text = str(item).strip()
            if not text:
                continue
            if text.startswith("-"):
                lines.append(text)
            else:
                lines.append(f"- {text}")
        return "\n".join(lines)

    return str(value)


def _normalize_suspicious(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value

    if isinstance(value, list):
        lines: list[str] = []
        for item in value:
            if item is None:
                continue

            # Preferred structured format: {"path": ..., "reason": ...}
            if isinstance(item, dict):
                path = str(item.get("path", "")).strip()
                reason = str(item.get("reason", "")).strip()
                if not path and not reason:
                    continue
                if path and reason:
                    text = f"{path} — {reason}"
                else:
                    text = path or reason
            else:
                text = str(item).strip()

            if not text:
                continue
            if text.startswith("-"):
                lines.append(text)
            else:
                lines.append(f"- {text}")
        return "\n".join(lines)

    return str(value)


def _locale_to_language(locale: str | None) -> str:
    loc = (locale or "").strip().lower()
    if not loc:
        return "the same language as the UI"
    if loc.startswith("pl"):
        return "Polish"
    if loc.startswith("en"):
        return "English"
    return loc

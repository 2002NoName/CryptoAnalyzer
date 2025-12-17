from __future__ import annotations

from pathlib import Path


def test_write_error_report_creates_file_and_redacts_env(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CRYPTOANALYZER_ERROR_DIR", str(tmp_path))
    monkeypatch.setenv("CRYPTOAI_API_KEY", "super-secret")
    monkeypatch.setenv("CRYPTOAI_ENDPOINT", "https://api.openai.com")

    from crypto_analyzer.shared.error_reporting import write_error_report

    try:
        raise ValueError("boom")
    except ValueError as exc:
        report = write_error_report(exc, where="test", context={"k": "v"})

    assert report.path.exists()
    text = report.path.read_text(encoding="utf-8", errors="replace")

    # contains error message
    assert "boom" in text

    # does not contain secret value
    assert "super-secret" not in text

    # does contain presence info
    assert "CRYPTOAI_API_KEY" in text

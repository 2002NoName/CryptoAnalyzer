from __future__ import annotations


def test_install_crash_reporting_does_not_raise(monkeypatch, tmp_path):
    # ensure it doesn't touch developer-local .env or write outside tmp
    monkeypatch.setenv("CRYPTOANALYZER_ERROR_DIR", str(tmp_path))
    monkeypatch.setenv("CRYPTOANALYZER_DISABLE_CRASH_HOOKS", "1")

    from crypto_analyzer.shared.error_reporting import install_crash_reporting

    install_crash_reporting()

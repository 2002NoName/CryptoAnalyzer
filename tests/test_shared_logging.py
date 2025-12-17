"""Unit tests for shared logging configuration."""

from __future__ import annotations

import logging
from unittest.mock import patch

from crypto_analyzer.shared.logging import configure_logging


def test_configure_logging_calls_structlog_and_basicconfig() -> None:
    with (
        patch("crypto_analyzer.shared.logging.logging.basicConfig") as basic_config,
        patch("crypto_analyzer.shared.logging.structlog.configure") as configure,
    ):
        configure_logging(level=logging.DEBUG)

    basic_config.assert_called_once()
    configure.assert_called_once()

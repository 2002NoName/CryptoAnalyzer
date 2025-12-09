"""Moduły współdzielone: konfiguracja, logowanie, i18n."""

from .config import AppConfig
from .logging import configure_logging

__all__ = ["AppConfig", "configure_logging"]

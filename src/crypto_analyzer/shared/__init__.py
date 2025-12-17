"""Moduły współdzielone: konfiguracja, logowanie, i18n."""

from .config import AppConfig
from .error_reporting import ErrorReport, get_error_reports_dir, write_error_report
from .logging import configure_logging

__all__ = [
	"AppConfig",
	"configure_logging",
	"ErrorReport",
	"get_error_reports_dir",
	"write_error_report",
]

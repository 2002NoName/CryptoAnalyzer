"""Testy interfejsu CLI."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from crypto_analyzer.cli import _build_parser, _run_analysis
from crypto_analyzer.core.models import DiskSource, SourceType


def test_parser_accepts_image_path() -> None:
    parser = _build_parser()
    args = parser.parse_args(["test.img"])
    assert args.source == Path("test.img")
    assert args.source_type == "image"


def test_parser_default_output_format() -> None:
    parser = _build_parser()
    args = parser.parse_args(["test.img"])
    assert args.format == "json"
    assert args.output == Path("report.json")


def test_parser_custom_output() -> None:
    parser = _build_parser()
    args = parser.parse_args(["test.img", "--output", "custom.csv", "--format", "csv"])
    assert args.output == Path("custom.csv")
    assert args.format == "csv"


def test_run_analysis_nonexistent_image(tmp_path) -> None:
    parser = _build_parser()
    args = parser.parse_args([str(tmp_path / "nonexistent.img")])
    result = _run_analysis(args)
    assert result == 1


def test_parser_accepts_physical_source_type() -> None:
    parser = _build_parser()
    args = parser.parse_args(["/dev/sda", "--source-type", "physical"])
    assert args.source_type == "physical"


def test_parser_supports_listing_physical_devices() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--source-type", "physical", "--list-physical"])
    assert args.source is None
    assert args.list_physical is True


def test_run_analysis_requires_image_path() -> None:
    parser = _build_parser()
    args = parser.parse_args([])
    result = _run_analysis(args)
    assert result == 1


def test_run_analysis_lists_physical_devices() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--source-type", "physical", "--list-physical"])

    with patch("crypto_analyzer.cli.TskPhysicalDiskDriver") as driver_cls:
        driver_instance = driver_cls.return_value
        driver_instance.enumerate_sources.return_value = [
            DiskSource(identifier="physical0", source_type=SourceType.PHYSICAL_DISK, display_name="Drive 0", path=Path("/dev/sda"))
        ]

        result = _run_analysis(args)

    assert result == 0
    driver_instance.close.assert_called_once()

"""Testy interfejsu CLI."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from crypto_analyzer.cli import _build_parser, _run_analysis


def test_parser_accepts_image_path() -> None:
    parser = _build_parser()
    args = parser.parse_args(["test.img"])
    assert args.image == Path("test.img")


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

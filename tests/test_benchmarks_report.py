"""Tests for benchmark report generation."""

from __future__ import annotations

import json

from crypto_analyzer.benchmarks.runner import run_all_benchmarks, write_report


def test_benchmark_report_writes_json_and_markdown(tmp_path) -> None:
    report = run_all_benchmarks(sample_size=8 * 1024, seeds=2, seed_base=100)
    written = write_report(report, output_dir=tmp_path, stem="report", formats=("json", "md"))

    paths = {p.name: p for p in written}
    assert "report.json" in paths
    assert "report.md" in paths

    payload = json.loads(paths["report.json"].read_text(encoding="utf-8"))
    assert "created_at" in payload
    assert "benchmarks" in payload
    assert isinstance(payload["benchmarks"], list)
    assert payload["benchmarks"], "expected at least one benchmark"
    names = {b.get("name") for b in payload["benchmarks"]}
    assert "heuristic_encryption" in names
    assert "signature_magic_bytes" in names

    md = paths["report.md"].read_text(encoding="utf-8")
    assert "# Benchmark Report" in md
    assert "## heuristic_encryption" in md
    assert "## signature_magic_bytes" in md

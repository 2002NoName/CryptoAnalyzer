"""Benchmark utilities and runners.

This package provides:
- repeatable synthetic datasets,
- benchmark runners,
- report generation (JSON/Markdown).
"""

from .runner import BenchmarkReport, run_all_benchmarks

__all__ = ["BenchmarkReport", "run_all_benchmarks"]

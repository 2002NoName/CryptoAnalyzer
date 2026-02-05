"""Compatibility wrapper for the new benchmark module.

Prefer running:
- `poetry run crypto-analyzer-benchmark`
"""

from __future__ import annotations

from pathlib import Path

from crypto_analyzer.benchmarks.runner import run_all_benchmarks, write_report


def main() -> int:
    report = run_all_benchmarks()
    output_dir = Path("benchmark_reports")
    written = write_report(report, output_dir=output_dir, formats=("json", "md"))
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

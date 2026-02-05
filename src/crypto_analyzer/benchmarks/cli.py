"""CLI entrypoint for running benchmarks and writing a report."""

from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path

from .runner import run_all_benchmarks, write_report


def _build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="crypto-analyzer-benchmark",
        description="Run CryptoAnalyzer benchmarks and generate an effectiveness report.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("benchmark_reports"),
        help="Directory for generated reports (default: benchmark_reports)",
    )
    parser.add_argument(
        "--stem",
        type=str,
        default="benchmark_report",
        help="Output filename stem (default: benchmark_report)",
    )
    parser.add_argument(
        "--format",
        action="append",
        dest="formats",
        choices=["json", "md"],
        help="Report format (can be provided multiple times). Default: json+md",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=256 * 1024,
        help="Sample size in bytes for synthetic samples (default: 262144)",
    )
    parser.add_argument(
        "--seeds",
        type=int,
        default=10,
        help="Number of seeds to evaluate (default: 10)",
    )
    parser.add_argument(
        "--seed-base",
        type=int,
        default=1337,
        help="Base seed value (default: 1337)",
    )
    parser.add_argument(
        "--images-dir",
        type=Path,
        default=Path("test_assets") / "generated",
        help="Directory containing generated test images for FS benchmark (default: test_assets/generated)",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    formats = tuple(args.formats) if args.formats else ("json", "md")

    report = run_all_benchmarks(
        sample_size=args.sample_size,
        seeds=args.seeds,
        seed_base=args.seed_base,
        images_dir=args.images_dir,
    )
    written = write_report(report, output_dir=args.output_dir, stem=args.stem, formats=formats)

    for path in written:
        print(path)

    return 0

"""Benchmark runner and report generation."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from crypto_analyzer.crypto_detection.signature_loader import load_default_signatures

from .filesystem import run_filesystem_benchmark
from .heuristics import run_heuristic_benchmark
from .signatures import run_signature_benchmark


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    created_at: str
    benchmarks: list[dict]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    def to_markdown(self) -> str:
        lines: list[str] = []
        lines.append("# Benchmark Report")
        lines.append("")
        lines.append(f"Generated: {self.created_at}")
        lines.append("")

        for bench in self.benchmarks:
            name = bench.get("name", "unknown")
            status = bench.get("status", "ok")
            lines.append(f"## {name}")
            lines.append("")

            if status != "ok":
                lines.append(f"Status: {status}")
                reason = bench.get("reason")
                if reason:
                    lines.append(f"Reason: {reason}")
                lines.append("")

            metrics = bench.get("metrics", {}) or {}
            if metrics:
                lines.append("### Metrics")
                for k in sorted(metrics):
                    v = metrics[k]
                    if isinstance(v, float):
                        lines.append(f"- {k}: {v:.4f}")
                    else:
                        lines.append(f"- {k}: {v}")
                lines.append("")

            confusion = bench.get("confusion", {}) or {}
            if confusion:
                lines.append("### Confusion")
                for k in sorted(confusion):
                    lines.append(f"- {k}: {confusion[k]}")
                lines.append("")

        return "\n".join(lines).rstrip() + "\n"


def _ok(payload: dict) -> dict:
    payload.setdefault("status", "ok")
    return payload


def _skipped(name: str, reason: str) -> dict:
    return {"name": name, "status": "skipped", "reason": reason, "metrics": {}, "confusion": {}}


def _error(name: str, error: Exception) -> dict:
    return {"name": name, "status": "error", "reason": str(error), "metrics": {}, "confusion": {}}


def run_all_benchmarks(
    *,
    sample_size: int = 256 * 1024,
    seeds: int = 10,
    seed_base: int = 1337,
    images_dir: Path | None = None,
) -> BenchmarkReport:
    results: list[dict] = []

    try:
        sigs = load_default_signatures()
        results.append(_ok(run_signature_benchmark(signatures=sigs).to_dict()))
    except Exception as exc:  # pragma: no cover
        results.append(_error("signature_magic_bytes", exc))

    try:
        results.append(
            _ok(
                run_heuristic_benchmark(
                    sample_size=sample_size,
                    seeds=seeds,
                    seed_base=seed_base,
                ).to_dict()
            )
        )
    except Exception as exc:  # pragma: no cover
        results.append(_error("heuristic_encryption", exc))

    # Optional: filesystem detection benchmark depends on having a generated image.
    images_dir = Path(images_dir) if images_dir is not None else Path("test_assets") / "generated"
    image = images_dir / "multi_volume.img"
    if not image.exists():
        results.append(_skipped("filesystem_detection", f"missing image: {image}"))
    else:
        try:
            results.append(_ok(run_filesystem_benchmark(image_path=image).to_dict()))
        except Exception as exc:  # pragma: no cover
            results.append(_error("filesystem_detection", exc))

    created_at = datetime.now(timezone.utc).isoformat()
    return BenchmarkReport(created_at=created_at, benchmarks=results)


def write_report(
    report: BenchmarkReport,
    *,
    output_dir: Path,
    stem: str = "benchmark_report",
    formats: tuple[str, ...] = ("json", "md"),
) -> list[Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    if "json" in formats:
        path = output_dir / f"{stem}.json"
        path.write_text(report.to_json(), encoding="utf-8")
        written.append(path)

    if "md" in formats:
        path = output_dir / f"{stem}.md"
        path.write_text(report.to_markdown(), encoding="utf-8")
        written.append(path)

    return written

"""Heuristic encryption detector benchmark.

This benchmark evaluates `HeuristicEncryptionDetector` on synthetic datasets.
The labels are synthetic ground-truth used for evaluation only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from crypto_analyzer.core.models import EncryptionStatus, FileSystemType, Volume
from crypto_analyzer.crypto_detection import HeuristicEncryptionDetector

from .synthetic import InMemoryDriver, deterministic_random_bytes, repeat_byte, zeros


@dataclass(frozen=True, slots=True)
class LabeledSample:
    name: str
    truth: EncryptionStatus
    data: bytes


@dataclass(frozen=True, slots=True)
class HeuristicBenchmarkResult:
    name: str
    sample_size: int
    seeds: int
    confusion: dict[str, int]
    metrics: dict[str, float]

    def to_dict(self) -> dict:
        return asdict(self)


def _make_volume(data: bytes) -> Volume:
    return Volume(identifier="synthetic", offset=0, size=len(data), filesystem=FileSystemType.UNKNOWN)


def _samples(*, size: int, seed: int) -> list[LabeledSample]:
    # IMPORTANT: this is a *synthetic* truth label. For ambiguous categories, we label UNKNOWN.
    return [
        LabeledSample(
            name="high_entropy_random",
            truth=EncryptionStatus.ENCRYPTED,
            data=deterministic_random_bytes(size, seed=seed),
        ),
        LabeledSample(
            name="all_zeros",
            truth=EncryptionStatus.UNKNOWN,
            data=zeros(size),
        ),
        LabeledSample(
            name="repeated_0xAA",
            truth=EncryptionStatus.NOT_DETECTED,
            data=repeat_byte(size, 0xAA),
        ),
    ]


def _confusion_key(truth: EncryptionStatus, pred: EncryptionStatus) -> str:
    return f"{truth.value} -> {pred.value}"


def _safe_div(num: float, den: float) -> float:
    return 0.0 if den == 0.0 else num / den


def _compute_metrics(confusion: dict[str, int]) -> dict[str, float]:
    # Focus: evaluate ENCRYPTED detection quality.
    tp = confusion.get("encrypted -> encrypted", 0)
    fp = (
        confusion.get("not_detected -> encrypted", 0)
        + confusion.get("unknown -> encrypted", 0)
    )
    fn = (
        confusion.get("encrypted -> not_detected", 0)
        + confusion.get("encrypted -> unknown", 0)
    )

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)

    total_non_encrypted = sum(
        confusion.get(k, 0)
        for k in (
            "not_detected -> encrypted",
            "not_detected -> not_detected",
            "not_detected -> unknown",
            "unknown -> encrypted",
            "unknown -> not_detected",
            "unknown -> unknown",
        )
    )
    fp_rate_non_encrypted = _safe_div(fp, total_non_encrypted)

    return {
        "encrypted_precision": float(precision),
        "encrypted_recall": float(recall),
        "encrypted_fp_rate_non_encrypted": float(fp_rate_non_encrypted),
    }


def run_heuristic_benchmark(*, sample_size: int = 256 * 1024, seeds: int = 10, seed_base: int = 1337) -> HeuristicBenchmarkResult:
    confusion: dict[str, int] = {}

    for i in range(int(seeds)):
        seed = int(seed_base) + i
        for sample in _samples(size=int(sample_size), seed=seed):
            detector = HeuristicEncryptionDetector(InMemoryDriver(sample.data))
            finding = detector.analyze_volume(_make_volume(sample.data))
            key = _confusion_key(sample.truth, finding.status)
            confusion[key] = confusion.get(key, 0) + 1

    metrics = _compute_metrics(confusion)

    return HeuristicBenchmarkResult(
        name="heuristic_encryption",
        sample_size=int(sample_size),
        seeds=int(seeds),
        confusion=confusion,
        metrics=metrics,
    )

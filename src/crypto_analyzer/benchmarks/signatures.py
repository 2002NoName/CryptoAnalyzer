"""Signature (magic bytes) benchmark.

This benchmark validates that configured signatures are detected correctly using
`SignatureBasedDetector` on synthetic buffers.

Scope
- Evaluates the signature engine and configuration (JSON) together.
- Does not require real disk images.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from crypto_analyzer.core.models import EncryptionStatus, FileSystemType, Volume
from crypto_analyzer.crypto_detection import SignatureBasedDetector
from crypto_analyzer.crypto_detection.signature_loader import EncryptionSignature, load_default_signatures

from .synthetic import InMemoryDriver


@dataclass(frozen=True, slots=True)
class SignatureBenchmarkResult:
    name: str
    samples: int
    passed: int
    failed: int
    confusion: dict[str, int]
    metrics: dict[str, float]

    def to_dict(self) -> dict:
        return asdict(self)


def _make_volume(size: int) -> Volume:
    return Volume(identifier="synthetic", offset=0, size=size, filesystem=FileSystemType.UNKNOWN)


def _place_matchers(buf: bytearray, *, signature: EncryptionSignature) -> None:
    # Inject patterns into the buffer so that signature.matches() will be True.
    # Note: matchers operate on the *read window* starting at signature.read_offset.
    base = int(signature.read_offset)

    for matcher in signature.matchers:
        # For 'contains' with no offset, place near the beginning of the read window.
        local_offset = 0 if matcher.offset is None else int(matcher.offset)
        absolute = base + local_offset
        end = absolute + len(matcher.pattern)
        if end > len(buf):
            raise ValueError("Buffer too small for matcher injection")
        buf[absolute:end] = matcher.pattern

    # If a version extractor exists, inject a non-zero value so extraction is exercised.
    if signature.version is not None and signature.version.type == "uint16-le":
        absolute = base + int(signature.version.offset)
        end = absolute + 2
        if end <= len(buf):
            buf[absolute:end] = (2).to_bytes(2, byteorder="little", signed=False)


def _confusion_key(expected_id: str, detected_id: str | None) -> str:
    return f"{expected_id} -> {detected_id or 'none'}"


def _safe_div(num: float, den: float) -> float:
    return 0.0 if den == 0.0 else num / den


def run_signature_benchmark(*, signatures: list[EncryptionSignature] | None = None) -> SignatureBenchmarkResult:
    sigs = list(signatures or load_default_signatures())

    confusion: dict[str, int] = {}
    passed = 0
    failed = 0

    for sig in sigs:
        # Build a buffer that covers read_offset + max_read.
        size = int(sig.read_offset) + int(sig.max_read)
        buf = bytearray(b"\x00" * size)
        _place_matchers(buf, signature=sig)

        driver = InMemoryDriver(bytes(buf))
        detector = SignatureBasedDetector(driver=driver, signatures=[sig])
        finding = detector.analyze_volume(_make_volume(len(buf)))

        ok = finding.status is sig.status and finding.algorithm == sig.name
        detected_id = sig.identifier if ok else None

        key = _confusion_key(sig.identifier, detected_id)
        confusion[key] = confusion.get(key, 0) + 1

        if ok:
            passed += 1
        else:
            failed += 1

    samples = len(sigs)
    accuracy = _safe_div(passed, samples)

    return SignatureBenchmarkResult(
        name="signature_magic_bytes",
        samples=samples,
        passed=passed,
        failed=failed,
        confusion=confusion,
        metrics={"accuracy": float(accuracy)},
    )

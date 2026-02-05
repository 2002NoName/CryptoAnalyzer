"""Moduły odpowiedzialne za wykrywanie szyfrowania.

Uwaga: Ten pakiet używa leniwych importów, aby uniknąć cyklicznych zależności
z warstwą `core` (np. `core.analysis_manager`).
"""

from __future__ import annotations

from importlib import import_module
from typing import Any


__all__ = [
	"EncryptionDetector",
	"EncryptionFinding",
	"SignatureBasedDetector",
	"HeuristicConfig",
	"HeuristicEncryptionDetector",
	"EncryptionSignature",
	"load_signatures",
	"load_default_signatures",
]


def __getattr__(name: str) -> Any:  # pragma: no cover
	if name in {"EncryptionDetector", "EncryptionFinding"}:
		mod = import_module("crypto_analyzer.crypto_detection.detectors")
		return getattr(mod, name)

	if name in {"SignatureBasedDetector"}:
		mod = import_module("crypto_analyzer.crypto_detection.signature_based")
		return getattr(mod, name)

	if name in {"HeuristicConfig", "HeuristicEncryptionDetector"}:
		mod = import_module("crypto_analyzer.crypto_detection.heuristics")
		return getattr(mod, name)

	if name in {"EncryptionSignature", "load_signatures", "load_default_signatures"}:
		mod = import_module("crypto_analyzer.crypto_detection.signature_loader")
		return getattr(mod, name)

	raise AttributeError(name)

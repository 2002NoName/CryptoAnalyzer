"""Testy modułu wczytującego sygnatury szyfrowania."""

from __future__ import annotations

import json

from crypto_analyzer.core.models import EncryptionStatus
from crypto_analyzer.crypto_detection.signature_loader import (
    SignatureMatcher,
    VersionExtractor,
    load_default_signatures,
    load_signatures,
)


def test_load_default_signatures_includes_bitlocker() -> None:
    signatures = load_default_signatures()
    assert any(signature.identifier == "bitlocker" for signature in signatures)


def test_load_signatures_from_custom_file(tmp_path) -> None:
    config = [
        {
            "id": "custom",
            "name": "Custom",
            "status": "encrypted",
            "max_read": 128,
            "matchers": [
                {"type": "equals", "pattern": "414243", "encoding": "hex", "offset": 0}
            ],
            "version": {"type": "ascii", "offset": 4, "length": 4},
        }
    ]
    path = tmp_path / "signatures.json"
    path.write_text(json.dumps(config), encoding="utf-8")

    signatures = load_signatures(path)

    assert len(signatures) == 1
    signature = signatures[0]
    assert signature.identifier == "custom"
    assert signature.status == EncryptionStatus.ENCRYPTED
    assert isinstance(signature.matchers[0], SignatureMatcher)
    assert isinstance(signature.version, VersionExtractor)

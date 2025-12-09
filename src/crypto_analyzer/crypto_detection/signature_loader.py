"""Ładowanie i interpretacja konfiguracyjnych sygnatur szyfrowania."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Iterable, List, Sequence

from crypto_analyzer.core.models import EncryptionStatus

_DATA_PACKAGE = "crypto_analyzer.data"
_DEFAULT_FILE = "encryption_signatures.json"


@dataclass(slots=True)
class SignatureMatcher:
    """Pojedyncza reguła dopasowania surowych danych."""

    type: str
    pattern: bytes
    offset: int | None = None

    def matches(self, data: bytes) -> bool:
        if self.type == "contains":
            if self.offset is None:
                return self.pattern in data
            end = self.offset + len(self.pattern)
            if end > len(data):
                return False
            return data[self.offset:end] == self.pattern
        if self.type == "equals":
            start = self.offset or 0
            end = start + len(self.pattern)
            if end > len(data):
                return False
            return data[start:end] == self.pattern
        raise ValueError(f"Nieobsługiwany typ matchera: {self.type}")


@dataclass(slots=True)
class VersionExtractor:
    """Definicja sposobu odczytu wersji z nagłówka."""

    type: str
    offset: int
    length: int | None = None

    def extract(self, data: bytes) -> str | None:
        if self.type == "uint16-le":
            length = self.length or 2
            if self.offset + length > len(data):
                return None
            value = int.from_bytes(data[self.offset : self.offset + length], byteorder="little")
            return str(value) if value else None
        if self.type == "ascii":
            length = self.length
            if length is None:
                raise ValueError("Ekstraktor ASCII wymaga podania długości")
            if self.offset + length > len(data):
                return None
            raw = data[self.offset : self.offset + length]
            text = raw.decode("ascii", errors="ignore").strip("\x00")
            return text or None
        raise ValueError(f"Nieobsługiwany typ ekstraktora: {self.type}")


@dataclass(slots=True)
class EncryptionSignature:
    """Konfiguracyjna definicja algorytmu szyfrowania."""

    identifier: str
    name: str
    status: EncryptionStatus
    matchers: Sequence[SignatureMatcher]
    details: str | None = None
    max_read: int = 4096
    version: VersionExtractor | None = None

    def matches(self, data: bytes) -> bool:
        return all(matcher.matches(data) for matcher in self.matchers)

    def extract_version(self, data: bytes) -> str | None:
        if self.version is None:
            return None
        return self.version.extract(data)


def _pattern_to_bytes(pattern: str, encoding: str | None) -> bytes:
    if encoding is None or encoding.lower() == "ascii":
        return pattern.encode("ascii")
    if encoding.lower() == "utf-8":
        return pattern.encode("utf-8")
    if encoding.lower() == "hex":
        return bytes.fromhex(pattern)
    raise ValueError(f"Nieobsługiwane kodowanie wzorca: {encoding}")


def _status_from_string(value: str) -> EncryptionStatus:
    mapping = {
        "encrypted": EncryptionStatus.ENCRYPTED,
        "not_detected": EncryptionStatus.NOT_DETECTED,
        "partial": EncryptionStatus.PARTIALLY_ENCRYPTED,
        "unknown": EncryptionStatus.UNKNOWN,
    }
    try:
        return mapping[value.lower()]
    except KeyError as exc:
        raise ValueError(f"Nieznany status szyfrowania: {value}") from exc


def _load_raw_config(path: Path | None = None) -> Iterable[dict]:
    if path is not None:
        with Path(path).open("r", encoding="utf-8") as handle:
            return json.load(handle)
    with resources.files(_DATA_PACKAGE).joinpath(_DEFAULT_FILE).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _parse_matchers(raw: Sequence[dict]) -> List[SignatureMatcher]:
    matchers: List[SignatureMatcher] = []
    for matcher in raw:
        pattern = _pattern_to_bytes(matcher["pattern"], matcher.get("encoding"))
        matchers.append(
            SignatureMatcher(
                type=matcher["type"],
                pattern=pattern,
                offset=matcher.get("offset"),
            )
        )
    return matchers


def _parse_version(raw: dict | None) -> VersionExtractor | None:
    if raw is None:
        return None
    return VersionExtractor(
        type=raw["type"],
        offset=raw["offset"],
        length=raw.get("length"),
    )


def _parse_signature(raw: dict) -> EncryptionSignature:
    return EncryptionSignature(
        identifier=raw["id"],
        name=raw["name"],
        status=_status_from_string(raw.get("status", "unknown")),
        matchers=_parse_matchers(raw["matchers"]),
        details=raw.get("details"),
        max_read=raw.get("max_read", 4096),
        version=_parse_version(raw.get("version")),
    )


def load_signatures(path: Path | None = None) -> List[EncryptionSignature]:
    """Wczytuje sygnatury z domyślnego zasobu lub wskazanego pliku."""

    raw_config = _load_raw_config(path)
    return [_parse_signature(entry) for entry in raw_config]


@lru_cache(maxsize=1)
def load_default_signatures() -> List[EncryptionSignature]:
    """Wczytuje i cache'uje sygnatury z zasobu pakietu."""

    return load_signatures()

"""Build a compact AI context from analysis results."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from crypto_analyzer.core.models import AnalysisResult, DirectoryNode, FileMetadata


@dataclass(slots=True)
class SuspiciousHit:
    path: str
    reason: str


_SUSPICIOUS_KEYWORDS = (
    "password",
    "pass",
    "seed",
    "mnemonic",
    "wallet",
    "metamask",
    "private",
    "id_rsa",
    "pem",
    "key",
    "keystore",
    "auth",
    "token",
    "secret",
)

_SUSPICIOUS_EXTENSIONS = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".kdbx",
    ".wallet",
    ".sqlite",
    ".db",
    ".dat",
)


def build_ai_context(
    result: AnalysisResult,
    *,
    ui_locale: str | None = None,
    max_files_per_volume: int = 200,
    max_suspicious: int = 50,
) -> dict[str, Any]:
    volumes_out: list[dict[str, Any]] = []

    for analysis in result.volumes:
        vol = analysis.volume
        finding = analysis.encryption

        files: list[dict[str, Any]] = []
        suspicious: list[dict[str, str]] = []

        if analysis.metadata is not None:
            all_files = list(_iter_files(analysis.metadata.root))
            suspicious_hits = find_suspicious(all_files, max_results=max_suspicious)

            # keep a limited sample of files (largest + most recent)
            largest = sorted(all_files, key=lambda f: int(getattr(f, "size", 0)), reverse=True)[: max_files_per_volume // 2]
            recent = sorted(all_files, key=_sort_key_mtime, reverse=True)[: max_files_per_volume // 2]

            # stable de-duplication by path
            seen: set[str] = set()
            for file_meta in largest + recent:
                p = str(file_meta.path)
                if p in seen:
                    continue
                seen.add(p)
                files.append(
                    {
                        "path": p,
                        "name": file_meta.name,
                        "size": file_meta.size,
                        "owner": file_meta.owner,
                        "created_at": file_meta.created_at,
                        "changed_at": file_meta.changed_at,
                        "modified_at": file_meta.modified_at,
                        "accessed_at": file_meta.accessed_at,
                        "attributes": list(file_meta.attributes),
                        "encryption": file_meta.encryption.value,
                    }
                )
                if len(files) >= max_files_per_volume:
                    break

            suspicious = [{"path": h.path, "reason": h.reason} for h in suspicious_hits]

        volumes_out.append(
            {
                "id": vol.identifier,
                "filesystem": analysis.filesystem.value,
                "offset": vol.offset,
                "size": vol.size,
                "encryption": {
                    "status": finding.status.value,
                    "algorithm": finding.algorithm,
                    "version": finding.version,
                },
                "totals": {
                    "files": analysis.metadata.total_files if analysis.metadata else 0,
                    "directories": analysis.metadata.total_directories if analysis.metadata else 0,
                },
                "files_sample": files,
                "suspicious_hits": suspicious,
            }
        )

    ui: dict[str, Any] | None = None
    if ui_locale:
        ui = {
            "locale": ui_locale,
            "language": _locale_to_language(ui_locale),
        }

    return {
        "ui": ui,
        "source": {
            "identifier": result.source.identifier,
            "type": result.source.source_type.value,
            "display_name": result.source.display_name,
            "path": str(result.source.path) if result.source.path else None,
        },
        "totals": {
            "volumes": len(result.volumes),
            "files": result.total_files(),
            "directories": result.total_directories(),
        },
        "volumes": volumes_out,
    }


def _locale_to_language(locale: str) -> str:
    loc = (locale or "").strip().lower()
    if loc.startswith("pl"):
        return "Polish"
    if loc.startswith("en"):
        return "English"
    return loc or "Unknown"


def find_suspicious(files: Iterable[FileMetadata], *, max_results: int = 50) -> list[SuspiciousHit]:
    hits: list[SuspiciousHit] = []
    for file_meta in files:
        path = str(file_meta.path)
        lowered = path.lower()

        for ext in _SUSPICIOUS_EXTENSIONS:
            if lowered.endswith(ext):
                hits.append(SuspiciousHit(path=path, reason=f"extension:{ext}"))
                break

        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in lowered:
                hits.append(SuspiciousHit(path=path, reason=f"keyword:{kw}"))
                break

        if len(hits) >= max_results:
            break

    # de-dup by path
    unique: dict[str, SuspiciousHit] = {}
    for hit in hits:
        unique.setdefault(hit.path, hit)
    return list(unique.values())[:max_results]


def _iter_files(node: DirectoryNode) -> Iterable[FileMetadata]:
    yield from node.files
    for sub in node.subdirectories:
        yield from _iter_files(sub)


def _sort_key_mtime(file_meta: FileMetadata) -> datetime:
    raw = file_meta.modified_at
    if not raw:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)

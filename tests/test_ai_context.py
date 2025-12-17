from __future__ import annotations

from pathlib import PurePosixPath

from crypto_analyzer.ai.context import _sort_key_mtime
from crypto_analyzer.core.models import FileMetadata


def test_sort_key_mtime_handles_naive_and_aware_datetimes() -> None:
    # None -> falls back to a timezone-aware minimum
    f_none = FileMetadata(
        name="a",
        path=PurePosixPath("/a"),
        size=0,
        owner=None,
        created_at=None,
        changed_at=None,
        modified_at=None,
        accessed_at=None,
    )

    # Naive ISO (no timezone) -> should be treated as UTC
    f_naive = FileMetadata(
        name="b",
        path=PurePosixPath("/b"),
        size=0,
        owner=None,
        created_at=None,
        changed_at=None,
        modified_at="2025-01-01T00:00:00",
        accessed_at=None,
    )

    # Aware ISO (with timezone)
    f_aware = FileMetadata(
        name="c",
        path=PurePosixPath("/c"),
        size=0,
        owner=None,
        created_at=None,
        changed_at=None,
        modified_at="2025-01-01T00:00:00+00:00",
        accessed_at=None,
    )

    keys = [_sort_key_mtime(f) for f in (f_none, f_naive, f_aware)]

    # All keys must be comparable (no naive/aware mix)
    assert all(k.tzinfo is not None for k in keys)

    # Sorting should not raise and should place the missing timestamp first.
    ordered = sorted([f_naive, f_none, f_aware], key=_sort_key_mtime)
    assert ordered[0] is f_none

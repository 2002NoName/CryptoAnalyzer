"""Unit tests for core task abstractions."""

from __future__ import annotations

import pytest

from crypto_analyzer.core.tasks import AnalysisTask


def test_analysis_task_run_not_implemented() -> None:
    task = AnalysisTask(name="x")
    with pytest.raises(NotImplementedError):
        task.run(lambda *_a, **_kw: None)  # type: ignore[arg-type]

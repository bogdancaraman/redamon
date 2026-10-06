"""A Jev-only hook flag set on the project reaches the scan under its own runtime key.

The camelCase column, the Python key and the registry entry are three spellings of
one setting. A typo in the `project.get(...)` mapping does not fail anything else:
the key silently falls back to its default (False) and the hook never runs. The
golden baselines cannot see it either, because every one of them stores False.

Each column is flipped on its own through the same resolve path the golden baselines
use (fetch, stealth, the AI-pipeline overrides), so a swapped mapping shows too.
"""
from __future__ import annotations

import pytest

from recon.tests.golden_settings import _defaults_row
from recon.tests.golden_settings_runner import resolve

JEV_ONLY_COLUMNS = ("ffufJevBasePaths", "httpxJevPageType", "resourceEnumJevToolHealth",
                    "hakrawlerJevSeedOrder", "serializedScanJevRank")


def _runtime_key(column: str) -> str:
    import settings_registry
    return settings_registry.fields()[column]["runtime_key"]


@pytest.mark.parametrize("column", JEV_ONLY_COLUMNS)
def test_a_jev_only_column_set_true_turns_on_exactly_its_runtime_key(column):
    settings = resolve({**_defaults_row(), column: True})
    assert settings[_runtime_key(column)] is True
    for other in JEV_ONLY_COLUMNS:
        if other != column:
            assert settings[_runtime_key(other)] is False, other


def test_every_jev_only_column_true_stays_true_even_with_ai_in_pipeline_off():
    """aiInPipeline gates them at each call site; the resolve path never resets them."""
    settings = resolve({**_defaults_row(), "aiInPipeline": False,
                        **{c: True for c in JEV_ONLY_COLUMNS}})
    assert [settings[_runtime_key(c)] for c in JEV_ONLY_COLUMNS] == [True] * len(JEV_ONLY_COLUMNS)

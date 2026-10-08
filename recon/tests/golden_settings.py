"""
The synthetic project rows the resolved-settings golden master runs against.

Comparing generated FILES catches almost nothing. A generator can emit a
perfectly plausible `settings['X'] = project.get('y', D)` that is byte-different
from the original in a way no diff flags as meaningful, and every risk in the
registry work shows up only in the VALUE the pipeline ends up running with.

So the golden master compares BEHAVIOUR: for each case below, the full settings
dict `fetch_project_settings` returns must be identical before and after any
change, key by key and value by value.

Each case exists to catch one named risk. None of them is a realistic project;
they are the corners a realistic project never reaches and a refactor lands in.

The baselines live in `fixtures/golden_settings/`, one JSON file per case, and
are regenerated ONLY by `python3 recon/tests/regen_golden_settings.py`. A test
run can never rewrite a baseline, because a baseline a test can silently update
is not a baseline.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tooling.scripts.prisma_project_columns import project_columns  # noqa: E402

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "golden_settings"


def _columns():
    return project_columns()


def _defaults_row() -> dict:
    """A project row carrying every column at its Prisma default."""
    row: dict = {"id": "golden-project", "userId": "golden-user", "name": "golden"}
    for name, col in _columns().items():
        value = col.default_value
        if value is None:
            continue
        row[name] = value
    return row


def _numeric_columns() -> list[str]:
    return [n for n, c in _columns().items() if c.kind in ("int", "float") and not c.is_list]


def _bounds_row(which: str) -> dict:
    """Every numeric at the min, the max, or zero, from the registry's bounds."""
    sys.path.insert(0, str(_REPO / "recon"))
    import settings_registry  # noqa: PLC0415

    row = _defaults_row()
    fields = settings_registry.fields()
    for name in _numeric_columns():
        entry = fields.get(name)
        if not entry or not entry.get("bounds"):
            continue
        if which == "zero":
            row[name] = 0
        else:
            raw = entry["bounds"][which]
            row[name] = raw if isinstance(raw, float) else int(raw)
    return row


def _empty_row() -> dict:
    """Every list and string empty, which is the `fallback: falsy` corner."""
    row = _defaults_row()
    for name, col in _columns().items():
        if col.is_list:
            row[name] = []
        elif col.kind == "string" and name not in ("id", "userId", "name"):
            row[name] = ""
    return row


def _roe_row(**over) -> dict:
    """A project with a live rate ceiling.

    The ceiling alone is what makes the limits live: `roeEnabled` is DERIVED
    now, so there is no second switch to set here and no way to write a ceiling
    that does not apply.
    """
    row = _defaults_row()
    row.update({"roeGlobalMaxRps": 3})
    row.update(over)
    return row


def cases() -> dict[str, dict]:
    """case name -> the project row the webapp API would return."""
    return {
        # baseline regression: nothing unusual, everything shipped
        "all_defaults": _defaults_row(),
        # a bound that excludes a legal value shows up here first
        "numeric_min": _bounds_row("min"),
        # a bound that clamps where the old code did not
        "numeric_max": _bounds_row("max"),
        # the zero_means class, and the puredns bypass
        "numeric_zero": _bounds_row("zero"),
        # the fallback: falsy class
        "empty_strings_and_lists": _empty_row(),
        # the cap list and all three bypasses
        "roe_3rps": _roe_row(),
        # every rate written at 0 UNDER a ceiling: unlimited must become 3
        "roe_3rps_zero_rates": {
            **_roe_row(),
            "ffufRate": 0,
            "arjunRateLimit": 0,
            "purednsRateLimit": 0,
            "webCachePoisonMaxRpsPerHost": 0,
            "takeoverRateLimit": 0,
            "jsluiceVerifyRateLimit": 0,
        },
        # every rate written far above the ceiling
        "roe_3rps_high_rates": {
            **_roe_row(),
            "naabuRateLimit": 5000,
            "nucleiRateLimit": 500,
            "httpxRateLimit": 500,
            "takeoverRateLimit": 500,
            "jsluiceVerifyRateLimit": 1000,
            "masscanRate": 100000,
        },
        # A ceiling written while the OLD master switch was off. This is the
        # one case the derivation deliberately changes: the ceiling used to be
        # inert and now applies, which is why the baseline for it moved.
        "ceiling_with_the_old_switch_off": {
            **_defaults_row(), "roeEnabled": False, "roeGlobalMaxRps": 3,
        },
        # The old switch ON with nothing behind it: no ceiling, no exclusions,
        # no window. The derivation reads it as inert, which it always was.
        "old_switch_on_with_no_limit": {
            **_defaults_row(), "roeEnabled": True, "roeGlobalMaxRps": 0,
        },
        # The two limits that are NOT a rate: each makes the limits live on its
        # own, and neither used to without the switch.
        "exclusions_only": {
            **_defaults_row(), "roeExcludedHosts": ["pay.target.test"],
        },
        "time_window_only": {
            **_defaults_row(), "roeTimeWindowEnabled": True,
        },
        # pass-ordering between stealth, RoE and the governor
        "stealth": {**_defaults_row(), "stealthMode": True},
        "stealth_with_roe": {**_roe_row(), "stealthMode": True},
        # targeting-specific branches
        "ip_mode": {
            **_defaults_row(),
            "ipMode": True,
            "targetIps": ["203.0.113.4", " 203.0.113.5 ", ""],
            "targetDomain": "",
        },
        "domain_batch": {
            **_defaults_row(),
            "domainBatchMode": True,
            "domainBatchHosts": ["a.example.com", "b.example.com"],
            "domainBatchGroups": [
                {"rootDomain": "example.com", "prefixes": ["a", "b"],
                 "hosts": ["a.example.com", "b.example.com"]}
            ],
        },
        # a docker image outside the allowlist: pinned, not honoured
        "hostile_docker_image": {
            **_defaults_row(),
            "nucleiDockerImage": "attacker/evil:latest",
            "naabuDockerImage": "attacker/evil:latest",
        },
        # a wordlist path outside the project directory
        "escaping_wordlist": {
            **_defaults_row(),
            "ffufWordlist": "/etc/shadow",
        },
    }

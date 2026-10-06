"""LIVE smoke: the TypeSafe API still answers the way jev_client expects.

Everything else about Jev is tested against mocks written from the docs and one
live capture. This is the only check that notices TypeSafe changing under us (a
status code, a field, the pinned model id), and a drifted API would otherwise
just make every hook fall back to its static list with nothing saying why.

Needs a real key in the environment, so it self-skips without one and is in the
live tier by its filename, never in the unit gate. It makes three calls and
spends about 270 input tokens (a hundredth of a cent).

  TYPESAFE_AI=<key> ./agentic/run_tests.sh live    (or any runner that passes the variable in)

The key is only ever sent by jev_client; nothing here prints it.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import jev_client  # noqa: E402
from jev_client import JevError  # noqa: E402

KEY = os.environ.get("TYPESAFE_AI", "").strip()

pytestmark = pytest.mark.skipif(
    not KEY, reason="TYPESAFE_AI is not set: no live TypeSafe key to test with")

# Well-formed but not a real key, so it reaches TypeSafe and is rejected there
# (a malformed key would be refused locally and prove nothing about the API).
BAD_KEY = "apikey_" + "0" * 36 + "_" + "f" * 64


async def test_models_listing_answers_200_and_names_the_model_family():
    models = await jev_client.list_models(KEY)
    assert isinstance(models, list) and models
    assert "jev-latest" in models


async def test_a_noul_ping_on_the_pinned_model_returns_a_valid_answer():
    question = {"ping": {"type": "noul", "instructions": "Is this a ping?"}}
    result = await jev_client.system_one(KEY, jev_client.JEV_MODEL, "ping", question)
    assert result["model"] == jev_client.JEV_MODEL
    noul = result["answers"]["ping"]["noul"]
    assert 0.0 <= noul <= 1.0


async def test_a_rejected_key_is_jev_auth():
    with pytest.raises(JevError) as err:
        await jev_client.list_models(BAD_KEY)
    assert err.value.error_type == "jev_auth"


# ---------------------------------------------------------------------------
# The per-item hooks, end to end against the live API. Synthetic items only
# (reserved .test names); about 2,500 input tokens for the four together.
# ---------------------------------------------------------------------------

import jev_hooks  # noqa: E402


async def test_ffuf_base_paths_live_ranks_only_the_candidates():
    cands = ["admin", "static/img", "api/v1"]
    out = await jev_hooks.ffuf_base_paths(KEY, cands, 2)
    assert len(out["ranked"]) == 2 and set(out["ranked"]) <= set(cands)
    assert len(out["scores"]) == 3 and all(0.0 <= s <= 1.0 for s in out["scores"])


async def test_page_type_live_labels_from_the_closed_set():
    page = {"url": "http://parked.example.test/", "host": "parked.example.test", "status_code": 200,
            "content_length": 900, "word_count": 40, "line_count": 12, "title": "This domain is for sale",
            "server": "nginx", "headers": {"Server": "nginx"},
            "body": "<html><h1>This domain is for sale</h1><p>Make an offer today.</p></html>"}
    out = await jev_hooks.page_type(KEY, [page])
    (label,) = out["labels"]
    assert label["page_class"] in set(jev_hooks.PAGE_CLASSES) | {"app"}
    assert 0 <= label["confidence"] <= 100


async def test_tool_health_live_returns_a_verdict():
    out = await jev_hooks.tool_health(KEY, "katana", 0, 31.0, 3, "context deadline exceeded")
    assert isinstance(out["transient"], bool) and 0 <= out["confidence"] <= 100


async def test_crawl_seed_order_live_scores_every_host():
    hosts = [{"hostname": "shop.example.test", "title": "Shop - Sign in", "server": "nginx",
              "status_code": 200, "content_length": 52000, "word_count": 3100, "url_count": 4},
             {"hostname": "cdn.example.test", "title": "", "server": "cloudfront",
              "status_code": 403, "content_length": 0, "word_count": 0, "url_count": 1}]
    out = await jev_hooks.crawl_seed_order(KEY, hosts)
    assert len(out["scores"]) == 2 and all(0.0 <= s <= 1.0 for s in out["scores"])


async def test_serialized_classify_live_answers_from_the_closed_set():
    """The only check that TypeSafe accepts the 14-option format choice as built."""
    blob = {"snippet": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3Rvcg",
            "transport": "cookie", "location": "rememberMe", "encoding_layers": ["base64"]}
    out = await jev_hooks.serialized_classify(KEY, [blob])
    (label,) = out["labels"]
    assert label["format"] in set(jev_hooks.SERIALIZED_FORMATS)
    assert 0 <= label["format_confidence"] <= 100 and 0 <= label["exploitability"] <= 100

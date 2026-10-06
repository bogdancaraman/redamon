"""Contract between the agent's per-item Jev hooks and the recon helpers that call them.

The agent and recon share no module, so each side keeps its own copy of a few
values that must match, and a drift fails silently: recon would reject every label
it does not know (so the hook falls back on every run), or send more items than the
request model accepts (a 422 on every call, also a silent fallback).

recon's constants are read from its source files in the mounted repo and evaluated
here; they are never re-typed in this test.

Runs inside the agent container.
"""
from __future__ import annotations

import ast
import sys
import typing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import jev_hooks  # noqa: E402

PLANNER = Path(__file__).resolve().parents[2] / "recon" / "helpers" / "ai_planner"


def _recon_constant(module: str, name: str):
    tree = ast.parse((PLANNER / f"{module}.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in recon/helpers/ai_planner/{module}.py")


def test_the_page_classes_are_the_same_closed_set():
    assert _recon_constant("page_type", "PAGE_CLASSES") == jev_hooks.PAGE_CLASSES


def test_recon_never_sends_more_pages_than_the_request_model_takes():
    import api
    limit = next(m.max_length for m in api.PageTypeRequest.model_fields["pages"].metadata
                 if hasattr(m, "max_length"))
    assert _recon_constant("page_type", "BATCH_SIZE") <= limit


def test_the_base_path_bounds_match():
    import api
    field = api.FfufBasePathsRequest.model_fields["candidates"]
    limit = next(m.max_length for m in field.metadata if hasattr(m, "max_length"))
    assert _recon_constant("ffuf_base_paths", "MAX_CANDIDATES") == jev_hooks.FFUF_BASE_PATHS_MAX == limit
    assert _recon_constant("ffuf_base_paths", "MAX_PATH_CHARS") == jev_hooks.FFUF_BASE_PATH_CHARS == 200


def test_the_crawl_host_bounds_match():
    import api
    limit = next(m.max_length for m in api.CrawlSeedOrderRequest.model_fields["hosts"].metadata
                 if hasattr(m, "max_length"))
    assert _recon_constant("crawl_seed_order", "MAX_HOSTS") == jev_hooks.CRAWL_SEED_HOSTS_MAX == limit


def test_the_tool_health_tools_match_the_request_model():
    import api
    allowed = typing.get_args(api.ToolHealthRequest.model_fields["tool"].annotation)
    assert set(allowed) == set(jev_hooks.TOOL_HEALTH_TOOLS)


def test_every_tool_recon_reports_is_one_the_agent_accepts():
    """recon names the tool in each empty-result report; a name the agent's Literal
    refuses would make every Jev call for that tool a 422."""
    import re
    helpers = PLANNER.parent / "resource_enum"
    reported = set()
    for path in helpers.glob("*_helpers.py"):
        reported |= set(re.findall(r'(?:check_empty|report_empty)\(\s*"([a-z_]+)"', path.read_text()))
    assert reported, "no empty-result report found in the recon helpers"
    assert reported <= set(jev_hooks.TOOL_HEALTH_TOOLS), reported - set(jev_hooks.TOOL_HEALTH_TOOLS)


def test_the_serialized_formats_are_the_same_closed_set():
    """recon's FORMATS is the detector's deser_format vocabulary; the agent adds
    "none". A format recon does not know fails validation on every answer."""
    assert tuple(_recon_constant("serialized_assess", "FORMATS")) + ("none",) == jev_hooks.SERIALIZED_FORMATS


def test_recon_never_sends_more_blobs_than_the_request_model_takes():
    import api
    limit = next(m.max_length for m in api.SerializedClassifyRequest.model_fields["blobs"].metadata
                 if hasattr(m, "max_length"))
    assert _recon_constant("serialized_assess", "BATCH_SIZE") <= limit


def test_the_serialized_transports_and_layers_match_the_request_model():
    import api
    fields = api.SerializedBlobItem.model_fields
    transports = set(typing.get_args(fields["transport"].annotation)) - {""}
    layers = set(typing.get_args(typing.get_args(fields["encoding_layers"].annotation)[0]))
    assert set(_recon_constant("serialized_assess", "TRANSPORTS")) == transports \
        == set(jev_hooks.SERIALIZED_TRANSPORTS)
    assert set(_recon_constant("serialized_assess", "LAYERS")) == layers \
        == set(jev_hooks.SERIALIZED_LAYERS)


def test_recon_clips_every_blob_field_within_the_request_model_bounds():
    """A field recon sends longer than the model allows is a 422 on every call."""
    import api
    fields = api.SerializedBlobItem.model_fields

    def limit(name):
        return next(m.max_length for m in fields[name].metadata if hasattr(m, "max_length"))

    assert _recon_constant("serialized_assess", "SNIPPET_CHARS") <= limit("snippet")
    assert _recon_constant("serialized_assess", "_MAGIC_CHARS") <= limit("magic")
    assert _recon_constant("serialized_assess", "_LOCATION_CHARS") <= limit("location")
    assert _recon_constant("serialized_assess", "_MAX_LAYERS") <= limit("encoding_layers")

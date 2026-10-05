"""/graph/triage: the MCP concurrency gate and the findings cap.

This endpoint is the backing store for the inbound MCP server's findings tools,
and it took NEITHER of the two bounds `/graph/exec` applies: no concurrency
ceiling, and no cap on how many rows the mixin returns. Both matter beyond
performance. The published guarantee is that graph reads from MCP run at most
five at a time across all tokens, and the contention lands on the operator's own
Priority Board, which reads the same data through this same endpoint.

The browser paths deliberately keep their previous behaviour: they set no
`source`, so nothing about how they are scheduled changes.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402


def _body(resp):
    import json

    return json.loads(bytes(resp.body).decode())


class _RecordingSemaphore:
    """Stands in for the real asyncio.Semaphore so entry is observable."""

    def __init__(self):
        self.entered = 0
        self.exited = 0

    async def __aenter__(self):
        self.entered += 1
        return self

    async def __aexit__(self, *exc):
        self.exited += 1
        return False


class _FakeTriageClient:
    driver = None

    def __init__(self):
        self.calls = []
        self.verdict_updates = True
        self.verdict_muted = False
        self.verdict_busy = False
        self.review_result = {"written": True, "label": "Vulnerability",
                              "accepted": {"verdict": "doubtful"},
                              "before": {"score": 70.0}, "after": {"score": 20.0}}

    def list_triage_findings(self, user_id, project_id, **kwargs):
        self.calls.append(("list_triage_findings", user_id, project_id, kwargs))
        return [{"id": "f1", "label": "Vulnerability"}]

    def count_triage_findings(self, user_id, project_id, **kwargs):
        self.calls.append(("count_triage_findings", user_id, project_id, kwargs))
        return 137

    def triage_facets(self, user_id, project_id):
        self.calls.append(("triage_facets", user_id, project_id))
        return {"total": 3, "decided_by": {"person": 1, "review": 1, "rules": 1}}

    def get_triage_detail(self, user_id, project_id, node_id, label=None):
        self.calls.append(("get_triage_detail", node_id, label))
        return {"found": True, "row": {"id": node_id, "label": "Vulnerability",
                                       "source": "nuclei"}, "group": [], "detector": {}}

    def write_review(self, user_id, project_id, node_id, decide, combine, label=None):
        self.calls.append(("write_review", node_id, label))
        return self.review_result

    def list_muted(self, user_id, project_id, limit=None, **kwargs):
        self.calls.append(("list_muted", user_id, project_id, limit, kwargs))
        return [{"id": "m1"}]

    def count_muted(self, user_id, project_id, **kwargs):
        self.calls.append(("count_muted", user_id, project_id, kwargs))
        return 42

    def muted_facets(self, user_id, project_id):
        self.calls.append(("muted_facets", user_id, project_id))
        return {"total": 1, "by_person": 1, "labels": {}, "rules": []}

    def unmute_findings(self, user_id, project_id, keys, skip_rule_mutes=False):
        self.calls.append(("unmute_findings", user_id, project_id, list(keys),
                           skip_rule_mutes))
        return {"unmuted": len(keys),
                "items": [{"key": k, "label": "Vulnerability", "muted_by": "rule:x/abc123"}
                          for k in keys]}

    def mute_finding(self, user_id, project_id, node_id, muted_by="", reason=""):
        self.calls.append(("mute_finding", node_id, muted_by, reason))
        return {"muted": True, "already": False, "label": "Vulnerability"}

    def mute_findings_delegated(self, user_id, project_id, **kwargs):
        self.calls.append(("mute_findings_delegated", user_id, project_id, kwargs))
        return {"items": [
            {"ref": "v1", "key": "v1", "label": "Vulnerability", "outcome": "muted"},
            {"ref": "v2", "key": "v2", "label": "Vulnerability", "outcome": "proven"},
            {"ref": "v3", "key": "v3", "label": "Secret", "outcome": "muted"},
        ], "not_found": []}

    def resolve_muted(self, user_id, project_id, **kwargs):
        self.calls.append(("resolve_muted", user_id, project_id, kwargs))
        return {"to_unmute": [], "skipped_rule_mute": [], "not_found": []}

    def set_human_verdict(self, user_id, project_id, node_id, status, reason,
                          channel="", verdict_by="", refuse_muted=False, **kwargs):
        self.calls.append(
            ("set_human_verdict", node_id, status, reason, channel, verdict_by,
             refuse_muted, kwargs))
        if self.verdict_busy:
            from graph_db.mixins.recon.triage_mixin import TriageWriteBusy
            raise TriageWriteBusy("timed out")
        if self.verdict_muted and refuse_muted:
            return {"updated": False, "reason": "muted", "label": "Vulnerability"}
        return {"updated": self.verdict_updates, "label": "Vulnerability",
                "before": {"score": 40.0}, "after": {"score": 75.0}}


class TriageGateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = _FakeTriageClient()
        self.sem = _RecordingSemaphore()
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "_graph_exec_mcp_semaphore", lambda: self.sem),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _req(self, **kw):
        base = dict(op="list_findings", user_id="u1", project_id="p1")
        base.update(kw)
        return api.GraphTriageRequest(**base)

    async def test_an_mcp_call_takes_the_concurrency_ceiling(self):
        await api.graph_triage(self._req(source="mcp"))
        self.assertEqual(self.sem.entered, 1)
        # And releases it, or the second caller waits forever.
        self.assertEqual(self.sem.exited, 1)

    async def test_a_browser_call_is_unchanged_and_takes_no_ceiling(self):
        # The operator's own Triage board must not be throttled by a bound that
        # exists for external tokens.
        resp = await api.graph_triage(self._req())
        self.assertEqual(self.sem.entered, 0)
        self.assertEqual(_body(resp)["total"], 137)

    async def test_every_mcp_op_is_gated_not_just_the_read(self):
        for op, extra in (
            ("list_findings", {}),
            ("list_muted", {}),
            ("human_verdict", {"node_id": "n1", "status": "confirmed"}),
        ):
            self.sem.entered = 0
            await api.graph_triage(self._req(op=op, source="mcp", **extra))
            self.assertEqual(self.sem.entered, 1, op)

    async def test_the_ceiling_is_released_even_when_the_op_raises(self):
        def boom(*a, **k):
            raise RuntimeError("neo4j down")

        self.client.list_triage_findings = boom
        resp = await api.graph_triage(self._req(source="mcp"))
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self.sem.exited, 1)


class TriageLimitTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = _FakeTriageClient()
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _req(self, **kw):
        base = dict(op="list_findings", user_id="u1", project_id="p1")
        base.update(kw)
        return api.GraphTriageRequest(**base)

    def _list_kwargs(self):
        for call in self.client.calls:
            if call[0] == "list_triage_findings":
                return call[3]
        self.fail("list_triage_findings was never called")

    async def test_no_limit_leaves_the_mixin_default_alone(self):
        await api.graph_triage(self._req())
        self.assertEqual(self._list_kwargs(), {})

    async def test_filters_reach_both_the_page_and_its_total(self):
        await api.graph_triage(self._req(decided_by="review", reviewed_via="mcp",
                                         review_current="stale"))
        want = {"decided_by": "review", "reviewed_via": "mcp", "review_current": "stale"}
        self.assertEqual(self._list_kwargs(), want)
        count = [c for c in self.client.calls if c[0] == "count_triage_findings"][0]
        self.assertEqual(count[3], want)

    async def test_an_unknown_filter_value_is_refused(self):
        for name in ("decided_by", "reviewed_via", "review_current"):
            resp = await api.graph_triage(self._req(**{name: "everything"}))
            self.assertEqual(resp.status_code, 400, name)
        self.assertEqual(self.client.calls, [])

    async def test_a_limit_is_passed_through(self):
        await api.graph_triage(self._req(limit=25))
        self.assertEqual(self._list_kwargs(), {"limit": 25})

    async def test_a_limit_is_clamped_to_the_mixin_ceiling(self):
        await api.graph_triage(self._req(limit=10_000_000))
        self.assertEqual(self._list_kwargs(), {"limit": api._TRIAGE_LIST_MAX})

    async def test_a_nonsense_limit_cannot_produce_an_empty_page(self):
        # 0 or a negative would return no rows beside a non-zero `total`, which
        # reads as "the scan found nothing" rather than "you asked for nothing".
        await api.graph_triage(self._req(limit=0))
        self.assertEqual(self._list_kwargs(), {"limit": 1})

    async def test_total_stays_the_UNCAPPED_count(self):
        # The whole point of `total`: a capped page must never pass for a
        # complete one.
        resp = await api.graph_triage(self._req(limit=1))
        body = _body(resp)
        self.assertEqual(len(body["findings"]), 1)
        self.assertEqual(body["total"], 137)


class TriageOpValidationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: _FakeTriageClient()),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    async def test_an_unknown_op_is_still_refused(self):
        resp = await api.graph_triage(
            api.GraphTriageRequest(op="drop_everything", user_id="u1", project_id="p1"))
        self.assertEqual(resp.status_code, 400)
        self.assertIn("unknown op", _body(resp)["error"])

    async def test_the_known_op_set_matches_what_the_handler_dispatches(self):
        self.assertEqual(
            api._TRIAGE_OPS,
            frozenset({"mute", "unmute", "unmute_many", "list_muted", "muted_facets",
                       "list_findings", "human_verdict", "preflight", "stop_run",
                       "mute_many", "resolve_muted", "mute_batch",
                       "finding_detail", "finding_evidence", "submit_review",
                       "triage_facets"}))

    async def test_a_node_op_without_a_node_id_is_refused_before_dispatch(self):
        for op in ("mute", "unmute", "human_verdict", "finding_detail",
                   "finding_evidence", "submit_review"):
            resp = await api.graph_triage(
                api.GraphTriageRequest(op=op, user_id="u1", project_id="p1"))
            self.assertEqual(resp.status_code, 400, op)



class VerdictProvenanceTests(unittest.IsolatedAsyncioTestCase):
    """A verdict records HOW it arrived and WHO it is by, and is audited.

    Before this, a verdict was audited nowhere: the webapp route wrote no audit
    row and this endpoint logged `log_event` only for mute and unmute. A
    decision that is durable and suppresses future AI review of that finding was
    invisible to any later reconstruction.
    """

    def setUp(self):
        self.client = _FakeTriageClient()
        self.events = []
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

        import session_log
        self._log = mock.patch.object(
            session_log, "log_event",
            lambda name, **kw: self.events.append((name, kw)))
        self._log.start()
        self.addCleanup(self._log.stop)

    def _req(self, **kw):
        base = dict(op="human_verdict", user_id="u1", project_id="p1",
                    node_id="v1", status="confirmed")
        base.update(kw)
        return api.GraphTriageRequest(**base)

    def _verdict_call(self):
        for c in self.client.calls:
            if c[0] == "set_human_verdict":
                return c
        self.fail("set_human_verdict was never called")

    async def test_the_verdict_rescores_through_combine_layers(self):
        from cypherfix_triage.layers import combine_props
        await api.graph_triage(self._req(label="Secret"))
        kwargs = self._verdict_call()[7]
        self.assertIs(kwargs["combine"], combine_props)
        self.assertEqual(kwargs["label"], "Secret")
        self.assertEqual(kwargs["token"], "")

    async def test_an_mcp_verdict_is_stamped_with_its_token_prefix(self):
        await api.graph_triage(self._req(source="mcp", token_prefix="rdmn_mcp_0a1b2c3d"))
        self.assertEqual(self._verdict_call()[7]["token"], "rdmn_mcp_0a1b2c3d")

    async def test_a_verdict_log_carries_no_text(self):
        await api.graph_triage(self._req(source="mcp", reason="an agent wrote this"))
        name, kw = self.events[0]
        self.assertEqual(name, "finding_verdict_set")
        self.assertNotIn("reason", kw)
        self.assertNotIn("an agent wrote this", repr(kw))
        self.assertEqual((kw["score_before"], kw["score_after"]), (40.0, 75.0))

    async def test_a_write_timeout_is_503_busy(self):
        self.client.verdict_busy = True
        resp = await api.graph_triage(self._req())
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(_body(resp)["code"], "busy")

    async def test_the_source_becomes_the_recorded_channel(self):
        await api.graph_triage(self._req(source="mcp"))
        self.assertEqual(self._verdict_call()[4], "mcp")

    async def test_a_browser_verdict_records_the_app_channel(self):
        await api.graph_triage(self._req())
        self.assertEqual(self._verdict_call()[4], "app")

    async def test_the_actor_defaults_to_the_tenant(self):
        await api.graph_triage(self._req())
        self.assertEqual(self._verdict_call()[5], "u1")

    async def test_an_explicit_actor_is_carried(self):
        await api.graph_triage(self._req(verdict_by="alice"))
        self.assertEqual(self._verdict_call()[5], "alice")

    async def test_a_verdict_is_logged(self):
        await api.graph_triage(self._req(source="mcp", reason="dup"))
        names = [n for n, _ in self.events]
        self.assertIn("finding_verdict_set", names)
        kw = dict(self.events[0][1])
        self.assertEqual(kw["node_id"], "v1")
        self.assertEqual(kw["status"], "confirmed")
        self.assertEqual(kw["channel"], "mcp")

    async def test_a_verdict_that_matched_NOTHING_is_not_logged_as_one(self):
        # `updated: false` means no node was touched. Logging it would record a
        # decision that was never made.
        self.client.verdict_updates = False
        await api.graph_triage(self._req())
        self.assertEqual(self.events, [])

    async def test_an_mcp_verdict_refuses_a_muted_finding(self):
        # A human verdict is a Mute Rules guard, so on a rule-muted finding it
        # would release the mute: an unmute by another name.
        await api.graph_triage(self._req(source="mcp"))
        self.assertIs(self._verdict_call()[6], True)

    async def test_a_browser_verdict_may_land_on_a_muted_finding(self):
        # The person clicking is the one who could unmute it anyway.
        await api.graph_triage(self._req())
        self.assertIs(self._verdict_call()[6], False)

    async def test_a_refused_verdict_is_not_logged_as_one(self):
        self.client.verdict_muted = True
        resp = await api.graph_triage(self._req(source="mcp"))
        self.assertEqual(_body(resp)["reason"], "muted")
        self.assertFalse(_body(resp)["updated"])
        self.assertEqual(self.events, [])


class MutedLimitTests(unittest.IsolatedAsyncioTestCase):
    """`list_muted` is unbounded for the UI and bounded for MCP.

    The Muted table counts the rows it receives, so a default cap would silently
    change an operator-visible number; the MCP path has no record cap on this
    dependency at all, so its bound has to travel with the request.
    """

    def setUp(self):
        self.client = _FakeTriageClient()
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _req(self, **kw):
        base = dict(op="list_muted", user_id="u1", project_id="p1")
        base.update(kw)
        return api.GraphTriageRequest(**base)

    def _limit(self):
        for c in self.client.calls:
            if c[0] == "list_muted":
                return c[3]
        self.fail("list_muted was never called")

    async def test_no_limit_stays_unbounded_for_the_browser(self):
        await api.graph_triage(self._req())
        self.assertIsNone(self._limit())

    async def test_a_limit_is_passed_through(self):
        await api.graph_triage(self._req(limit=2000, source="mcp"))
        self.assertEqual(self._limit(), 2000)

    async def test_a_limit_is_clamped_to_the_same_ceiling(self):
        await api.graph_triage(self._req(limit=10_000_000))
        self.assertEqual(self._limit(), api._TRIAGE_LIST_MAX)

    async def test_a_nonsense_limit_cannot_produce_an_empty_page(self):
        await api.graph_triage(self._req(limit=0))
        self.assertEqual(self._limit(), 1)


class MutedNodesPagingTests(unittest.IsolatedAsyncioTestCase):
    """Muted Nodes pages the muted list instead of loading every row.

    The filters and the page reach the mixin untouched, and the total is
    counted with the SAME filters, so "N of M" describes what is on screen.
    """

    def setUp(self):
        self.client = _FakeTriageClient()
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _call(self, name):
        for c in self.client.calls:
            if c[0] == name:
                return c
        self.fail(f"{name} was never called")

    async def test_filters_and_page_reach_the_mixin(self):
        resp = await api.graph_triage(api.GraphTriageRequest(
            op="list_muted", user_id="u1", project_id="p1", limit=50, offset=100,
            label="Secret", muted_via="rule", rule="rule:secret/abc123",
            search="aws", order="person_first"))
        body = _body(resp)
        listed = self._call("list_muted")
        self.assertEqual(listed[3], 50)
        self.assertEqual(listed[4]["offset"], 100)
        self.assertEqual(listed[4]["order"], "person_first")
        self.assertEqual(listed[4]["label"], "Secret")
        counted = self._call("count_muted")
        # The same filters, minus the page: the total is of the filtered set.
        for key in ("label", "muted_via", "rule", "search", "live_rules"):
            self.assertEqual(counted[3][key], listed[4][key], key)
        self.assertNotIn("offset", counted[3])
        self.assertEqual(body["total"], 42)

    async def test_a_negative_offset_is_no_offset(self):
        await api.graph_triage(api.GraphTriageRequest(
            op="list_muted", user_id="u1", project_id="p1", offset=-5))
        self.assertIsNone(self._call("list_muted")[4]["offset"])

    async def test_unmute_many_passes_the_keys_and_returns_what_was_unmuted(self):
        with mock.patch("session_log.log_event") as log:
            resp = await api.graph_triage(api.GraphTriageRequest(
                op="unmute_many", user_id="u1", project_id="p1", keys=["v1", "v2"]))
        body = _body(resp)
        self.assertEqual(self._call("unmute_findings")[3], ["v1", "v2"])
        self.assertEqual([i["key"] for i in body["items"]], ["v1", "v2"])
        # One log line per finding actually unmuted, naming what had muted it.
        self.assertEqual(log.call_count, 2)
        self.assertEqual(log.call_args.kwargs["muted_by"], "rule:x/abc123")

    async def test_facets(self):
        resp = await api.graph_triage(api.GraphTriageRequest(
            op="muted_facets", user_id="u1", project_id="p1"))
        self.assertEqual(_body(resp)["total"], 1)


class GateAcknowledgementTests(unittest.IsolatedAsyncioTestCase):
    """The caller can tell whether this agent understood the MCP gate.

    Without it, a deploy that rebuilds only the webapp leaves an older agent
    that ignores `source`, `limit` and `verdict_by`, answers 200, and silently
    applies neither the concurrency ceiling nor the verdict provenance.
    """

    def setUp(self):
        self.client = _FakeTriageClient()
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    async def test_an_mcp_call_is_acknowledged(self):
        resp = await api.graph_triage(api.GraphTriageRequest(
            op="list_findings", user_id="u1", project_id="p1", source="mcp"))
        self.assertIs(_body(resp)["mcp_gated"], True)

    async def test_a_browser_call_gets_no_extra_field(self):
        resp = await api.graph_triage(api.GraphTriageRequest(
            op="list_findings", user_id="u1", project_id="p1"))
        self.assertNotIn("mcp_gated", _body(resp))

    async def test_the_acknowledgement_does_not_displace_the_result(self):
        resp = await api.graph_triage(api.GraphTriageRequest(
            op="list_findings", user_id="u1", project_id="p1", source="mcp"))
        body = _body(resp)
        self.assertEqual(body["total"], 137)
        self.assertEqual(len(body["findings"]), 1)


#: A body `mute_many` accepts, so each refusal test changes exactly one thing.
_GOOD_MUTE_MANY = dict(
    op="mute_many", user_id="u1", project_id="p1", source="mcp",
    keys=["v1", "v2", "v3"], graph_ids=["812"], exempt_pairs=[["Secret", "s9"]],
    muted_by="u1", reason="dev-only banner, confirmed by the owner",
    token_prefix="rdmn_mcp_ab12cd34",
)


class _TriageEndpointCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = _FakeTriageClient()
        self.events = []
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "_graph_exec_mcp_semaphore", lambda: _RecordingSemaphore()),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])
        import session_log
        self._log = mock.patch.object(
            session_log, "log_event",
            lambda name, **kw: self.events.append((name, kw)))
        self._log.start()
        self.addCleanup(self._log.stop)

    async def call(self, **kw):
        return await api.graph_triage(api.GraphTriageRequest(**kw))

    def calls(self, name):
        return [c for c in self.client.calls if c[0] == name]


class RuleAttributionIsNeverForgedTests(_TriageEndpointCase):
    """Only the Mute Rules sweep writes rule mutes, and it does not come here.

    A `muted_by` starting `rule:` makes the prune delete the finding (a rule
    mute is not a person's decision) and lets a sweep release or re-attribute
    it, so any master-key caller could turn a mute into a deletion.
    """

    async def test_a_rule_muted_by_is_refused_on_the_ui_mute(self):
        resp = await self.call(op="mute", user_id="u1", project_id="p1",
                               node_id="v1", muted_by="rule:vuln.nuclei/abc123")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(self.calls("mute_finding"), [])

    async def test_a_rule_muted_by_is_refused_on_the_mcp_mute(self):
        resp = await self.call(**{**_GOOD_MUTE_MANY, "muted_by": "rule:secret/x"})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(self.calls("mute_findings_delegated"), [])

    async def test_a_person_mute_still_works(self):
        resp = await self.call(op="mute", user_id="u1", project_id="p1",
                               node_id="v1", muted_by="u1", reason="noise")
        self.assertEqual(resp.status_code, 200)
        self.assertIs(_body(resp)["already"], False)

    async def test_an_already_muted_finding_is_not_logged_as_a_new_mute(self):
        # The mute left it as it was; a log line would credit this person
        # with a rule's or an agent's mute.
        self.client.mute_finding = lambda *a, **k: {
            "muted": True, "already": True, "label": "Vulnerability"}
        resp = await self.call(op="mute", user_id="u1", project_id="p1",
                               node_id="v1", muted_by="u1", reason="noise")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual([e for e in self.events if e[0] == "finding_muted"], [])

    async def test_a_fresh_mute_is_still_logged(self):
        await self.call(op="mute", user_id="u1", project_id="p1",
                        node_id="v1", muted_by="u1", reason="noise")
        (name, kw), = [e for e in self.events if e[0] == "finding_muted"]
        self.assertEqual(kw["node_id"], "v1")

    async def test_the_unconfigured_key_refusal_says_nothing_was_done(self):
        # Coded, so the webapp reports the write as not done, not as an
        # unknown outcome that keeps an MCP token's budget spent.
        with mock.patch.object(api, "master_key_is_weak", lambda: True):
            resp = await self.call(**_GOOD_MUTE_MANY)
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(_body(resp)["code"], "not_configured")
        self.assertEqual(self.calls("mute_findings_delegated"), [])

    async def test_a_ui_mute_reason_is_capped(self):
        resp = await self.call(op="mute", user_id="u1", project_id="p1",
                               node_id="v1", reason="x" * 501)
        self.assertEqual(resp.status_code, 400)


class MuteManyValidationTests(_TriageEndpointCase):
    """`mute_many` is the MCP mute, re-checked here for any master-key caller."""

    async def assertRefused(self, **override):
        resp = await self.call(**{**_GOOD_MUTE_MANY, **override})
        self.assertEqual(resp.status_code, 400, override)
        self.assertEqual(self.calls("mute_findings_delegated"), [], override)
        return _body(resp)["error"]

    async def test_the_good_body_is_accepted(self):
        resp = await self.call(**_GOOD_MUTE_MANY)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(self.calls("mute_findings_delegated")), 1)

    async def test_a_browser_source_is_refused(self):
        await self.assertRefused(source=None)

    async def test_absent_exemptions_are_refused_not_read_as_none(self):
        # Absent would silently re-hide everything a person unmuted.
        self.assertIn("exempt_pairs", await self.assertRefused(exempt_pairs=None))

    async def test_an_empty_exemption_list_is_a_real_answer(self):
        resp = await self.call(**{**_GOOD_MUTE_MANY, "exempt_pairs": []})
        self.assertEqual(resp.status_code, 200)

    async def test_a_malformed_pair_is_refused(self):
        await self.assertRefused(exempt_pairs=[["Secret"]])

    async def test_a_bad_token_prefix_is_refused(self):
        for bad in (None, "", "rdmn_mcp_", "rdmn_mcp_ZZ12cd34", "rdmn_mcp_ab12cd34ef",
                    "rdmn_mcp_ab12cd34\n[audit] forged", "rdmn_mcp_ab12cd34\n"):
            with self.subTest(prefix=bad):
                await self.assertRefused(token_prefix=bad)

    async def test_the_reason_is_required_and_bounded(self):
        for bad in (None, "", "  a ", "x" * 501):
            with self.subTest(reason=(bad or "")[:10]):
                await self.assertRefused(reason=bad)

    async def test_at_least_one_ref(self):
        await self.assertRefused(keys=[], graph_ids=[])

    async def test_at_most_5000_keys_or_node_ids(self):
        self.assertEqual(api._MCP_MUTE_MAX, 5000)
        await self.assertRefused(keys=[f"v{i}" for i in range(5001)])
        await self.assertRefused(graph_ids=[str(i) for i in range(5001)])

    async def test_keys_and_node_ids_over_the_cap_together_are_refused_not_truncated(self):
        # A full list of each would pass a per-list check, and the mixin would
        # then mute the first of the combined set and report the rest neither
        # done nor not found.
        self.assertIn("at most 5000", await self.assertRefused(
            keys=[f"v{i}" for i in range(2501)], graph_ids=[str(i) for i in range(2500)]))
        resp = await self.call(**{**_GOOD_MUTE_MANY, "keys": [f"v{i}" for i in range(2500)],
                                  "graph_ids": [str(i) for i in range(2500)]})
        self.assertEqual(resp.status_code, 200)

    async def test_graph_ids_are_digits_only(self):
        for bad in ("12a", "-1", "1 OR 1=1", "1" * 19, "12\n", "\u00b2"):
            with self.subTest(gid=bad):
                await self.assertRefused(graph_ids=[bad])

    async def test_the_arguments_reach_the_mixin(self):
        await self.call(**{**_GOOD_MUTE_MANY, "reason": "  noisy banner  "})
        kwargs = self.calls("mute_findings_delegated")[0][3]
        self.assertEqual(kwargs["keys"], ["v1", "v2", "v3"])
        self.assertEqual(kwargs["graph_ids"], ["812"])
        self.assertEqual(kwargs["exempt_pairs"], [["Secret", "s9"]])
        self.assertEqual(kwargs["muted_by"], "u1")
        self.assertEqual(kwargs["reason"], "noisy banner")
        self.assertEqual(kwargs["token_prefix"], "rdmn_mcp_ab12cd34")

    async def test_the_write_is_acknowledged_as_gated(self):
        resp = await self.call(**_GOOD_MUTE_MANY)
        self.assertIs(_body(resp)["mcp_gated"], True)

    async def test_one_log_line_per_finding_actually_muted(self):
        await self.call(**_GOOD_MUTE_MANY)
        muted = [kw for name, kw in self.events if name == "finding_muted"]
        self.assertEqual([kw["node_id"] for kw in muted], ["v1", "v3"])
        for kw in muted:
            self.assertEqual(kw["channel"], "mcp")
            self.assertEqual(kw["token_prefix"], "rdmn_mcp_ab12cd34")
            self.assertEqual(kw["reason"], "dev-only banner, confirmed by the owner")


class UnmuteScopeTests(_TriageEndpointCase):
    async def test_an_mcp_unmute_skips_rule_mutes_unless_asked(self):
        await self.call(op="unmute_many", user_id="u1", project_id="p1",
                        keys=["v1"], source="mcp")
        self.assertIs(self.calls("unmute_findings")[0][4], True)

    async def test_an_mcp_unmute_with_the_flag_releases_rule_mutes(self):
        await self.call(op="unmute_many", user_id="u1", project_id="p1",
                        keys=["v1"], source="mcp", include_rule_mutes=True)
        self.assertIs(self.calls("unmute_findings")[0][4], False)

    async def test_the_ui_unmute_is_unchanged(self):
        await self.call(op="unmute_many", user_id="u1", project_id="p1", keys=["v1"])
        self.assertIs(self.calls("unmute_findings")[0][4], False)

    async def test_the_mcp_ceiling_is_5000_and_the_ui_ceiling_500(self):
        keys = [f"v{i}" for i in range(501)]
        resp = await self.call(op="unmute_many", user_id="u1", project_id="p1", keys=keys)
        self.assertEqual(resp.status_code, 400)
        resp = await self.call(op="unmute_many", user_id="u1", project_id="p1",
                               keys=keys, source="mcp")
        self.assertEqual(resp.status_code, 200)
        resp = await self.call(op="unmute_many", user_id="u1", project_id="p1",
                               keys=[f"v{i}" for i in range(5000)], source="mcp")
        self.assertEqual(resp.status_code, 200)
        resp = await self.call(op="unmute_many", user_id="u1", project_id="p1",
                               keys=[f"v{i}" for i in range(5001)], source="mcp")
        self.assertEqual(resp.status_code, 400)

    async def test_an_unmute_is_logged_with_its_channel(self):
        await self.call(op="unmute_many", user_id="u1", project_id="p1",
                        keys=["v1"], source="mcp")
        (name, kw), = [e for e in self.events if e[0] == "finding_unmuted"]
        self.assertEqual(kw["channel"], "mcp")

    async def test_resolve_passes_the_flag_and_node_ids(self):
        resp = await self.call(op="resolve_muted", user_id="u1", project_id="p1",
                               keys=["v1"], graph_ids=["77"], source="mcp",
                               include_rule_mutes=True)
        self.assertIs(_body(resp)["mcp_gated"], True)
        kwargs = self.calls("resolve_muted")[0][3]
        self.assertEqual(kwargs, {"keys": ["v1"], "graph_ids": ["77"],
                                  "include_rule_mutes": True})

    async def test_keys_and_node_ids_over_the_ceiling_together_are_refused_not_truncated(self):
        for op in ("resolve_muted", "unmute_many"):
            with self.subTest(op=op):
                resp = await self.call(op=op, user_id="u1", project_id="p1", source="mcp",
                                       keys=[f"v{i}" for i in range(3000)],
                                       graph_ids=[str(i) for i in range(2001)])
                self.assertEqual(resp.status_code, 400)
        self.assertEqual(self.calls("resolve_muted") + self.calls("unmute_findings"), [])

    async def test_resolve_refuses_a_non_digit_node_id(self):
        resp = await self.call(op="resolve_muted", user_id="u1", project_id="p1",
                               graph_ids=["n1"], source="mcp")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(self.calls("resolve_muted"), [])


class MutedTokenFilterTests(_TriageEndpointCase):
    async def test_the_token_filter_reaches_the_page_and_its_count(self):
        await self.call(op="list_muted", user_id="u1", project_id="p1",
                        token="rdmn_mcp_ab12cd34", muted_via="mcp")
        listed = self.calls("list_muted")[0][4]
        counted = self.calls("count_muted")[0][3]
        self.assertEqual(listed["token"], "rdmn_mcp_ab12cd34")
        self.assertEqual(counted["token"], "rdmn_mcp_ab12cd34")
        self.assertEqual(listed["muted_via"], "mcp")

    async def test_a_token_that_is_not_a_prefix_is_refused(self):
        resp = await self.call(op="list_muted", user_id="u1", project_id="p1",
                               token="rdmn_mcp_ab12cd34ef567890")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(self.calls("list_muted"), [])


class LayeredOpsTests(unittest.IsolatedAsyncioTestCase):
    """The single-finding ops, how they are scheduled, and what they answer."""

    def setUp(self):
        self.client = _FakeTriageClient()
        self.sem = _RecordingSemaphore()
        self.threaded = []
        self.events = []

        async def recording_to_thread(fn, *args, **kwargs):
            self.threaded.append(fn)
            return fn(*args, **kwargs)

        import session_log
        from cypherfix_triage import finding_ops
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "_graph_exec_mcp_semaphore", lambda: self.sem),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
            mock.patch.object(api.asyncio, "to_thread", recording_to_thread),
            mock.patch.object(finding_ops, "read_finding_row",
                              lambda *a, **k: {"id": "v1", "source": "nuclei", "name": "x",
                                               "raw_response": "body text here"}),
            mock.patch.object(session_log, "log_event",
                              lambda name, **kw: self.events.append((name, kw))),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _review(self, **kw):
        base = dict(op="submit_review", user_id="u1", project_id="p1", node_id="v1",
                    source="mcp", token_prefix="rdmn_mcp_0a1b2c3d", evidence_hash="a" * 40,
                    review={"verdict": "doubtful", "why": "SECRET-WHY-TEXT"})
        base.update(kw)
        return api.GraphTriageRequest(**base)

    async def test_every_op_runs_off_the_event_loop(self):
        """B18: a browser write waiting on a publish lock stalled every coroutine."""
        for op, extra in (("list_findings", {}), ("triage_facets", {}),
                          ("preflight", {}), ("finding_detail", {"node_id": "v1"}),
                          ("human_verdict", {"node_id": "v1", "status": "confirmed"}),
                          ("muted_facets", {})):
            self.threaded.clear()
            await api.graph_triage(api.GraphTriageRequest(
                op=op, user_id="u1", project_id="p1", **extra))
            self.assertEqual(len(self.threaded), 1, op)
            self.assertEqual(self.sem.entered, 0, op)

    async def test_every_answer_acknowledges_the_layered_publish(self):
        for source in (None, "mcp"):
            resp = await api.graph_triage(api.GraphTriageRequest(
                op="list_findings", user_id="u1", project_id="p1", source=source))
            self.assertIs(_body(resp)["layered_publish"], True)

    async def test_a_review_is_the_mcp_door_only(self):
        resp = await api.graph_triage(self._review(source=None))
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn("write_review", [c[0] for c in self.client.calls])

    async def test_a_review_needs_a_real_token_prefix_and_hash(self):
        for bad in (dict(token_prefix="nope"), dict(evidence_hash="xyz"),
                    dict(evidence_hash="A" * 40), dict(review=None)):
            resp = await api.graph_triage(self._review(**bad))
            self.assertEqual(resp.status_code, 400, bad)

    async def test_a_finding_id_and_label_are_validated(self):
        for bad in (dict(node_id="v1; MATCH (n) DETACH DELETE n"),
                    dict(label="Domain"), dict(node_id="x" * 201)):
            resp = await api.graph_triage(self._review(**bad))
            self.assertEqual(resp.status_code, 400, bad)

    async def test_a_review_takes_the_mcp_ceiling_and_is_logged_without_text(self):
        resp = await api.graph_triage(self._review())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.sem.entered, 1)
        name, kw = self.events[0]
        self.assertEqual(name, "finding_review_submitted")
        self.assertEqual(kw["verdict"], "doubtful")
        self.assertEqual((kw["score_before"], kw["score_after"]), (70.0, 20.0))
        self.assertNotIn("SECRET-WHY-TEXT", repr(self.events))

    async def test_a_refused_review_is_not_logged_as_one(self):
        self.client.review_result = {"written": False, "reason": "decided_by_person"}
        resp = await api.graph_triage(self._review())
        self.assertEqual(_body(resp)["reason"], "decided_by_person")
        self.assertEqual(self.events, [])

    async def test_a_stop_stays_on_the_loop(self):
        """It touches the in-process run registry."""
        await api.graph_triage(api.GraphTriageRequest(
            op="stop_run", user_id="u1", project_id="p1"))
        self.assertEqual(self.threaded, [])


if __name__ == "__main__":
    unittest.main()

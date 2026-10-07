"""
Deep-review test battery for the cache oracle (recon/cache_scan/oracle.py) and
its settings/scanner wiring.

Layers:
  * UNIT        — pure helpers (_classify_status, _positive_max_age, _body_hash,
                  _behavioral_probe) and detect_cache_oracle header logic.
  * INTEGRATION — scanner._scan_one_url passes the behavioural settings through,
                  and project_settings maps the DB fields to WEB_CACHE_POISON_*.
  * SMOKE       — every public entry point returns a well-formed result and never
                  raises across a representative spread of inputs.
  * REGRESSION  — the original public contract (the behaviour shipped before the
                  silent-cache work) still holds.

Run:
  python3 -m unittest recon.tests.test_oracle_deep -v
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from recon.cache_scan import oracle, scanner  # noqa: E402
from recon import project_settings  # noqa: E402


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------
class FakeResp:
    """Minimal stand-in for requests.Response (only .text/.headers used)."""

    def __init__(self, headers=None, body="<x/>", status=200):
        self.headers = headers or {}
        self.text = body
        self.status_code = status


class HeaderSession:
    """Returns a fixed header set (and body) on every GET; counts calls."""

    def __init__(self, headers, body="<x/>"):
        self._headers = headers
        self._body = body
        self.calls = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        self.calls += 1
        return FakeResp(dict(self._headers), self._body)


class SequenceSession:
    """Returns a different header set per call (last one repeats); counts calls."""

    def __init__(self, sequence, body="<x/>"):
        self._seq = sequence
        self._body = body
        self.calls = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        idx = min(self.calls, len(self._seq) - 1)
        self.calls += 1
        return FakeResp(dict(self._seq[idx]), self._body)


class FrozenDateSession:
    """Silent cache: no cache headers, but a frozen Date and a stable body."""

    def __init__(self, body="<cached/>"):
        self._body = body
        self.calls = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        self.calls += 1
        return FakeResp({"date": "Mon, 30 Jun 2026 10:00:00 GMT"}, self._body)


class LiveOriginSession:
    """Live origin: no cache headers, Date advances and body changes per call."""

    def __init__(self):
        self.calls = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        self.calls += 1
        return FakeResp({"date": f"Mon, 30 Jun 2026 10:00:0{self.calls} GMT"},
                        body=f"<n={self.calls}/>")


class RaisingSession:
    """Always raises a RequestException (network failure)."""

    def get(self, *a, **k):
        import requests
        raise requests.RequestException("boom")


class RecordingSleep:
    def __init__(self):
        self.calls = []

    def __call__(self, d):
        self.calls.append(d)


_NO_SLEEP = lambda *_: None


# ===========================================================================
# UNIT — pure helpers
# ===========================================================================
class TestPositiveMaxAge(unittest.TestCase):
    def test_max_age_positive(self):
        self.assertTrue(oracle._positive_max_age("public, max-age=600"))

    def test_max_age_zero(self):
        self.assertFalse(oracle._positive_max_age("max-age=0, must-revalidate"))

    def test_s_maxage_positive(self):
        # CDN-only directive — was previously unrecognised.
        self.assertTrue(oracle._positive_max_age("s-maxage=300"))

    def test_s_maxage_zero(self):
        self.assertFalse(oracle._positive_max_age("s-maxage=0"))

    def test_any_positive_wins(self):
        self.assertTrue(oracle._positive_max_age("max-age=0, s-maxage=300"))

    def test_no_directive(self):
        self.assertFalse(oracle._positive_max_age("no-cache, private"))


class TestClassifyStatus(unittest.TestCase):
    def test_hit(self):
        self.assertEqual(oracle._classify_status("x-cache", "HIT"), "hit")

    def test_miss(self):
        self.assertEqual(oracle._classify_status("x-cache", "MISS"), "miss")

    def test_expired_is_miss(self):
        self.assertEqual(oracle._classify_status("x-cache-status", "EXPIRED"), "miss")

    def test_stale(self):
        self.assertEqual(oracle._classify_status("x-cache-status", "STALE"), "stale")

    def test_revalidated_is_stale(self):
        self.assertEqual(oracle._classify_status("x-cache-status", "REVALIDATED"), "stale")

    def test_dynamic_is_uncacheable(self):
        self.assertEqual(oracle._classify_status("cf-cache-status", "DYNAMIC"), "uncacheable")

    def test_none_is_uncacheable(self):
        self.assertEqual(oracle._classify_status("cf-cache-status", "NONE"), "uncacheable")

    def test_bypass_is_uncacheable(self):
        self.assertEqual(oracle._classify_status("cf-cache-status", "BYPASS"), "uncacheable")

    def test_varnish_two_ids_hit(self):
        self.assertEqual(oracle._classify_status("x-varnish", "1001 2002"), "hit")

    def test_varnish_one_id_miss(self):
        self.assertEqual(oracle._classify_status("x-varnish", "1001"), "miss")

    def test_varnish_non_numeric_unknown(self):
        self.assertEqual(oracle._classify_status("x-varnish", "cache-node-a"), "")

    def test_unknown_value_returns_empty(self):
        self.assertEqual(oracle._classify_status("x-cache", "weirdvalue"), "")


class TestBodyHash(unittest.TestCase):
    def test_deterministic(self):
        a = oracle._body_hash(FakeResp(body="hello"))
        b = oracle._body_hash(FakeResp(body="hello"))
        self.assertEqual(a, b)

    def test_differs_on_change(self):
        a = oracle._body_hash(FakeResp(body="hello"))
        b = oracle._body_hash(FakeResp(body="world"))
        self.assertNotEqual(a, b)

    def test_missing_text_is_safe(self):
        class NoText:
            pass
        self.assertIsInstance(oracle._body_hash(NoText()), str)


class TestBehavioralProbe(unittest.TestCase):
    def test_frozen_date_same_body_detects(self):
        ok, ind, sig = oracle._behavioral_probe("u", FrozenDateSession(), 10, True, 1.1, _NO_SLEEP)
        self.assertTrue(ok)
        self.assertEqual(ind, "behavioral:frozen-date")
        self.assertTrue(sig)

    def test_advancing_date_rejects(self):
        ok, _, _ = oracle._behavioral_probe("u", LiveOriginSession(), 10, True, 1.1, _NO_SLEEP)
        self.assertFalse(ok)

    def test_no_date_header_rejects(self):
        sess = HeaderSession({"content-type": "text/html"})
        ok, _, _ = oracle._behavioral_probe("u", sess, 10, True, 1.1, _NO_SLEEP)
        self.assertFalse(ok)
        self.assertEqual(sess.calls, 1)  # bails after the first request (no Date)

    def test_frozen_date_changing_body_rejects(self):
        # Same Date but body changes => not a simple cached entry.
        class FrozenDateMovingBody:
            def __init__(self):
                self.n = 0
            def get(self, *a, **k):
                self.n += 1
                return FakeResp({"date": "Mon, 30 Jun 2026 10:00:00 GMT"}, body=f"<{self.n}/>")
        ok, _, _ = oracle._behavioral_probe("u", FrozenDateMovingBody(), 10, True, 1.1, _NO_SLEEP)
        self.assertFalse(ok)

    def test_network_error_is_safe(self):
        ok, _, _ = oracle._behavioral_probe("u", RaisingSession(), 10, True, 1.1, _NO_SLEEP)
        self.assertFalse(ok)


# ===========================================================================
# UNIT — detect_cache_oracle
# ===========================================================================
class TestDetectHeaders(unittest.TestCase):
    def _info(self, headers, **kw):
        kw.setdefault("behavioral", False)
        return oracle.detect_cache_oracle("https://x/", HeaderSession(headers), **kw)

    def test_x_cache_hit(self):
        info = self._info({"x-cache": "hit"})
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])
        self.assertTrue(info["cache_layer"])

    def test_via_presence(self):
        info = self._info({"via": "1.1 varnish"})
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["cache_layer"])

    def test_surrogate_control_presence(self):
        info = self._info({"surrogate-control": "max-age=3600"})
        self.assertTrue(info["cacheable"])

    def test_varnish_numeric_hit(self):
        info = self._info({"x-varnish": "1001 2002"})
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_squid_lookup(self):
        info = self._info({"x-cache-lookup": "HIT from proxy:3128"})
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_nginx_stale(self):
        info = self._info({"x-cache-status": "STALE"})
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_age_positive_is_hit(self):
        info = self._info({"age": "42"})
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_age_zero_cacheable_not_hit(self):
        info = self._info({"age": "0"})
        self.assertTrue(info["cacheable"])
        self.assertFalse(info["saw_hit"])

    def test_cloudflare_dynamic_not_cacheable(self):
        info = self._info({"cf-cache-status": "DYNAMIC"})
        self.assertFalse(info["cacheable"])
        self.assertTrue(info["cache_layer"])  # CDN present, just not caching

    def test_cloudflare_none_not_cacheable(self):
        info = self._info({"cf-cache-status": "NONE"})
        self.assertFalse(info["cacheable"])
        self.assertTrue(info["cache_layer"])

    def test_cache_control_public(self):
        info = self._info({"cache-control": "public, max-age=600"})
        self.assertTrue(info["cacheable"])
        self.assertFalse(info["cache_layer"])  # eligibility, not a proven cache layer

    def test_cache_control_s_maxage_only(self):
        info = self._info({"cache-control": "s-maxage=600"})
        self.assertTrue(info["cacheable"])

    def test_cache_control_no_store_blocks(self):
        info = self._info({"cache-control": "private, no-store, max-age=600"})
        self.assertFalse(info["cacheable"])

    def test_cache_control_no_cache_alone_not_cacheable(self):
        info = self._info({"cache-control": "no-cache"})
        self.assertFalse(info["cacheable"])

    def test_cache_control_max_age_zero_not_cacheable(self):
        info = self._info({"cache-control": "max-age=0"})
        self.assertFalse(info["cacheable"])

    def test_vary_captured(self):
        info = self._info({"x-cache": "hit", "vary": "X-Forwarded-Host"})
        self.assertEqual(info["vary"], "X-Forwarded-Host")

    def test_result_shape_contract(self):
        info = self._info({"x-cache": "hit"})
        self.assertEqual(
            set(info.keys()),
            {"cacheable", "indicator", "signals", "saw_hit", "cache_layer", "vary", "behavioral"},
        )

    def test_signals_deduped(self):
        # Two identical probes => the same "x-cache: hit" signal must appear once.
        info = self._info({"x-cache": "hit"})
        self.assertEqual(info["signals"].count("x-cache: hit"), 1)


class TestDetectProbeCounts(unittest.TestCase):
    def test_early_break_after_two_when_cacheable(self):
        sess = HeaderSession({"x-cache": "hit"})
        oracle.detect_cache_oracle("https://x/", sess, behavioral=False)
        self.assertEqual(sess.calls, 2)

    def test_third_probe_catches_warm_on_third(self):
        sess = SequenceSession([
            {"cf-cache-status": "DYNAMIC"},
            {"cf-cache-status": "DYNAMIC"},
            {"cf-cache-status": "HIT"},
        ])
        info = oracle.detect_cache_oracle("https://x/", sess, behavioral=False)
        self.assertTrue(info["cacheable"])
        self.assertEqual(sess.calls, 3)

    def test_silent_url_request_accounting(self):
        sess = FrozenDateSession()
        sleep = RecordingSleep()
        info = oracle.detect_cache_oracle("https://x/", sess, behavioral=True, sleep_fn=sleep)
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["behavioral"])
        self.assertEqual(sess.calls, 5)        # 3 header probes + 2 behavioural
        self.assertEqual(len(sleep.calls), 1)  # one delay between behavioural probes


class TestDetectBehavioral(unittest.TestCase):
    def test_silent_cache_detected(self):
        info = oracle.detect_cache_oracle("https://x/", FrozenDateSession(),
                                          behavioral=True, sleep_fn=_NO_SLEEP)
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["behavioral"])
        self.assertEqual(info["indicator"], "behavioral:frozen-date")

    def test_live_origin_not_detected(self):
        info = oracle.detect_cache_oracle("https://x/", LiveOriginSession(),
                                          behavioral=True, sleep_fn=_NO_SLEEP)
        self.assertFalse(info["cacheable"])
        self.assertFalse(info["behavioral"])

    def test_behavioral_disabled_skips_fallback(self):
        sess = FrozenDateSession()
        info = oracle.detect_cache_oracle("https://x/", sess, behavioral=False)
        self.assertFalse(info["cacheable"])
        self.assertLessEqual(sess.calls, 3)  # header probes only, no behavioural pair

    def test_delay_zero_falls_back_to_default(self):
        sleep = RecordingSleep()
        info = oracle.detect_cache_oracle("https://x/", FrozenDateSession(),
                                          behavioral=True, behavioral_delay=0, sleep_fn=sleep)
        self.assertTrue(info["cacheable"])
        self.assertEqual(sleep.calls, [1.1])  # clamped away from the unsafe 0

    def test_negative_delay_falls_back(self):
        sleep = RecordingSleep()
        oracle.detect_cache_oracle("https://x/", FrozenDateSession(),
                                   behavioral=True, behavioral_delay=-3, sleep_fn=sleep)
        self.assertEqual(sleep.calls, [1.1])

    def test_custom_delay_passed_through(self):
        sleep = RecordingSleep()
        oracle.detect_cache_oracle("https://x/", FrozenDateSession(),
                                   behavioral=True, behavioral_delay=2.5, sleep_fn=sleep)
        self.assertEqual(sleep.calls, [2.5])

    def test_network_error_returns_not_cacheable(self):
        info = oracle.detect_cache_oracle("https://x/", RaisingSession(), behavioral=True)
        self.assertFalse(info["cacheable"])
        self.assertEqual(info["indicator"], "")
        # contract still intact on the error path
        self.assertIn("behavioral", info)


# ===========================================================================
# UNIT — response_cache_state
# ===========================================================================
class TestResponseCacheState(unittest.TestCase):
    def s(self, headers):
        return oracle.response_cache_state(FakeResp(headers))

    def test_hit(self):
        self.assertEqual(self.s({"x-cache": "HIT"}), "hit")

    def test_miss(self):
        self.assertEqual(self.s({"x-cache": "MISS"}), "miss")

    def test_stale_is_hit(self):
        self.assertEqual(self.s({"x-cache-status": "STALE"}), "hit")

    def test_dynamic_is_miss(self):
        self.assertEqual(self.s({"cf-cache-status": "DYNAMIC"}), "miss")

    def test_none_is_miss(self):
        self.assertEqual(self.s({"cf-cache-status": "NONE"}), "miss")

    def test_varnish_two_hit(self):
        self.assertEqual(self.s({"x-varnish": "1001 2002"}), "hit")

    def test_varnish_one_miss(self):
        self.assertEqual(self.s({"x-varnish": "1001"}), "miss")

    def test_age_zero_is_no_evidence(self):
        # A same-second hit also carries Age: 0, and scoring rejects an explicit miss.
        self.assertEqual(self.s({"age": "0"}), "unknown")

    def test_any_layer_hit_beats_an_inner_layer_miss(self):
        # A cache replays the headers it stored: Varnish in front of Drupal keeps the
        # stored X-Drupal-Cache: MISS, Cloudflare passes an origin's X-Cache: MISS on.
        self.assertEqual(self.s({"x-drupal-cache": "MISS", "x-varnish": "1001 2002", "age": "3"}), "hit")
        self.assertEqual(self.s({"x-cache": "MISS", "cf-cache-status": "HIT"}), "hit")
        self.assertEqual(self.s({"x-cache": "MISS", "age": "12"}), "hit")

    def test_age_positive_hit(self):
        self.assertEqual(self.s({"age": "9"}), "hit")

    def test_unknown(self):
        self.assertEqual(self.s({}), "unknown")

    def test_explicit_hit_beats_varnish_single_id(self):
        # Regression guard for the precedence fix: an explicit HIT must win over
        # a single Varnish id that would otherwise read as a miss.
        self.assertEqual(self.s({"x-cache": "HIT", "x-varnish": "1001"}), "hit")

    def test_bad_age_unknown(self):
        self.assertEqual(self.s({"age": "notanumber"}), "unknown")


# ===========================================================================
# INTEGRATION — scanner wiring
# ===========================================================================
class TestScannerWiring(unittest.TestCase):
    def _capture(self, settings):
        captured = {}

        def fake_detect(url, session, timeout=10, verify_ssl=True, *,
                        behavioral=True, behavioral_delay=1.1, **kw):
            captured.update(behavioral=behavioral, behavioral_delay=behavioral_delay,
                            timeout=timeout, verify_ssl=verify_ssl)
            return {"cacheable": False, "indicator": "", "signals": [], "saw_hit": False,
                    "cache_layer": False, "vary": "", "behavioral": False}

        with mock.patch.object(scanner.oracle, "detect_cache_oracle", fake_detect):
            url, entry, cc = scanner._scan_one_url(
                "https://t/", {}, {}, settings,
                min_conf=0.8, cross_vantage=False, timeout=10, verify_ssl=True)
        return captured, (url, entry, cc)

    def test_settings_flow_through(self):
        captured, (url, entry, cc) = self._capture({
            "WEB_CACHE_POISON_BEHAVIORAL_ORACLE": False,
            "WEB_CACHE_POISON_BEHAVIORAL_DELAY": 2.5,
        })
        self.assertFalse(captured["behavioral"])
        self.assertEqual(captured["behavioral_delay"], 2.5)
        self.assertEqual(cc, 0)                    # not cacheable -> URL skipped
        self.assertFalse(entry["oracle"]["cacheable"])

    def test_defaults_when_settings_absent(self):
        captured, _ = self._capture({})
        self.assertTrue(captured["behavioral"])     # default on
        self.assertEqual(captured["behavioral_delay"], 1.1)


# ===========================================================================
# INTEGRATION — project_settings DB-field mapping
# ===========================================================================
class TestSettingsMapping(unittest.TestCase):
    def _fetch(self, project):
        import types

        # fetch_project_settings does `from helpers.key_rotation import KeyRotator`
        # (a container-only module). Stub the package so the real mapping body runs.
        fake_helpers = types.ModuleType("helpers")
        fake_kr = types.ModuleType("helpers.key_rotation")

        class _FakeKR:
            def __init__(self, *a, **k):
                pass

        fake_kr.KeyRotator = _FakeKR
        fake_helpers.key_rotation = fake_kr

        resp = mock.Mock()
        resp.raise_for_status = lambda: None
        resp.json = lambda: project
        with mock.patch.dict(sys.modules, {"helpers": fake_helpers,
                                           "helpers.key_rotation": fake_kr}), \
                mock.patch("requests.get", return_value=resp):
            return project_settings.fetch_project_settings("p1", "http://webapp")

    def test_defaults_present_in_default_settings(self):
        self.assertEqual(project_settings.DEFAULT_SETTINGS["WEB_CACHE_POISON_BEHAVIORAL_ORACLE"], True)
        self.assertEqual(project_settings.DEFAULT_SETTINGS["WEB_CACHE_POISON_BEHAVIORAL_DELAY"], 1.1)

    def test_explicit_values_mapped(self):
        s = self._fetch({"webCachePoisonBehavioralOracle": False,
                         "webCachePoisonBehavioralDelay": 3.0})
        self.assertFalse(s["WEB_CACHE_POISON_BEHAVIORAL_ORACLE"])
        self.assertEqual(s["WEB_CACHE_POISON_BEHAVIORAL_DELAY"], 3.0)

    def test_missing_keys_fall_back_to_defaults(self):
        s = self._fetch({})  # project row without the new fields
        self.assertTrue(s["WEB_CACHE_POISON_BEHAVIORAL_ORACLE"])
        self.assertEqual(s["WEB_CACHE_POISON_BEHAVIORAL_DELAY"], 1.1)


# ===========================================================================
# SMOKE — public entry points never raise, always well-formed
# ===========================================================================
class TestSmoke(unittest.TestCase):
    HEADER_CASES = [
        {}, {"x-cache": "hit"}, {"x-cache": "miss"}, {"cf-cache-status": "DYNAMIC"},
        {"cf-cache-status": "NONE"}, {"age": "5"}, {"via": "1.1 squid"},
        {"x-varnish": "1 2"}, {"x-varnish": "1"}, {"cache-control": "public, max-age=60"},
        {"cache-control": "private, no-store"}, {"x-cache-status": "STALE"},
        {"warning": "110 - response is stale"},
    ]

    def test_detect_oracle_well_formed_everywhere(self):
        keys = {"cacheable", "indicator", "signals", "saw_hit", "cache_layer", "vary", "behavioral"}
        for h in self.HEADER_CASES:
            info = oracle.detect_cache_oracle("https://x/", HeaderSession(h),
                                              behavioral=True, sleep_fn=_NO_SLEEP)
            self.assertEqual(set(info.keys()), keys, msg=f"headers={h}")
            self.assertIsInstance(info["cacheable"], bool)
            self.assertIsInstance(info["signals"], list)

    def test_response_cache_state_only_valid_labels(self):
        for h in self.HEADER_CASES:
            self.assertIn(oracle.response_cache_state(FakeResp(h)), {"hit", "miss", "unknown"})


# ===========================================================================
# REGRESSION — original public contract preserved
# ===========================================================================
class TestRegression(unittest.TestCase):
    """These assertions match the behaviour shipped before the silent-cache work."""

    def test_x_cache_hit_still_detected(self):
        info = oracle.detect_cache_oracle("https://x/", HeaderSession({"x-cache": "hit", "age": "5"}))
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_no_signals_not_cacheable(self):
        info = oracle.detect_cache_oracle(
            "https://x/", HeaderSession({"content-type": "text/html"}), behavioral=False)
        self.assertFalse(info["cacheable"])

    def test_response_cache_state_original_four(self):
        self.assertEqual(oracle.response_cache_state(FakeResp({"x-cache": "HIT"})), "hit")
        self.assertEqual(oracle.response_cache_state(FakeResp({"x-cache": "MISS"})), "miss")
        self.assertEqual(oracle.response_cache_state(FakeResp({"age": "0"})), "unknown")
        self.assertEqual(oracle.response_cache_state(FakeResp({})), "unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)

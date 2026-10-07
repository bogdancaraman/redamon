"""Unit tests for the web cache poisoning scanner (recon/cache_scan)."""
import json
import os
import sys
import tempfile
import unittest

import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from recon.cache_scan import wcvs_runner, scoring, safety, normalizers, hypotheses, buster
from recon.cache_scan import oracle, confirm, scanner


# ---------------------------------------------------------------------------
# Test doubles: a stateful fake HTTP layer that models a real cache.
# ---------------------------------------------------------------------------
class FakeResponse:
    def __init__(self, body="", headers=None, status=200):
        self.text = body
        self.headers = headers or {}
        self.status_code = status


class VulnerableCacheSession:
    """Models an unkeyed-header cache poisoning vulnerability.

    The cache keys ONLY on URL (the injected header is unkeyed). When a request
    carries the trigger header, the backend reflects its value into the body and
    the cache stores that body under the URL key. Subsequent header-less requests
    to the same URL get the stored (poisoned) body back as a cache HIT.
    """

    def __init__(self, trigger_header="X-Forwarded-Host"):
        self.trigger_header = trigger_header.lower()
        self.store = {}  # url -> body
        self.headers_base = {"User-Agent": "x"}

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        headers = headers or {}
        injected = None
        for k, v in headers.items():
            if k.lower() == self.trigger_header:
                injected = v
        if injected is not None:
            body = f"<script src=//{injected}/x.js></script>"
            self.store[url] = body
            return FakeResponse(body, {"x-cache": "miss"})
        if url in self.store:
            return FakeResponse(self.store[url], {"x-cache": "hit", "age": "12"})
        return FakeResponse("<clean/>", {"x-cache": "miss"})


class SafeCacheSession:
    """Cache that does NOT reflect the header (not vulnerable)."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        return FakeResponse("<clean/>", {"x-cache": "hit", "age": "5"})


class NoCacheSession:
    """No cache headers at all."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        return FakeResponse("<dynamic/>", {"content-type": "text/html"})


class DifferentialCacheSession:
    """Models NON-REFLECTIVE cache poisoning.

    Injecting the trigger header makes the backend emit a redirect (a changed
    Location + status), which the cache stores under the URL key. No marker is
    echoed back, so only the differential detector (status/location/body diff)
    can catch it. Clean follow-ups return the stored poisoned redirect as a HIT.
    """

    def __init__(self, trigger_header="X-Forwarded-Proto"):
        self.trigger_header = trigger_header.lower()
        self.store = {}  # url -> (status, location)

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        headers = headers or {}
        injected = any(k.lower() == self.trigger_header for k in headers)
        if injected:
            self.store[url] = (301, "https://evil.example/login")
            return FakeResponse("", {"x-cache": "miss", "location": "https://evil.example/login"}, status=301)
        if url in self.store:
            status, loc = self.store[url]
            return FakeResponse("", {"x-cache": "hit", "age": "5", "location": loc}, status=status)
        return FakeResponse("<clean/>", {"x-cache": "miss"}, status=200)


class DynamicNoiseSession:
    """A dynamic, NOT-vulnerable page whose body changes on every request.

    The baseline-stability guard must treat the body dimension as untrusted and
    refuse to raise a differential finding (no false positive)."""

    def __init__(self):
        self.n = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        self.n += 1
        return FakeResponse(f"<page id={self.n}/>", {"x-cache": "hit", "age": "3"}, status=200)


class StatusPoisonCacheSession:
    """Non-reflective CPDoS: the trigger header makes the backend 403; the cache
    stores that status under the URL key and replays it to clean requests."""

    def __init__(self, trigger="X-Forwarded-Proto"):
        self.trigger = trigger.lower()
        self.store = {}

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        headers = headers or {}
        if any(k.lower() == self.trigger for k in headers):
            self.store[url] = 403
            return FakeResponse("Forbidden", {"x-cache": "miss"}, status=403)
        if url in self.store:
            return FakeResponse("Forbidden", {"x-cache": "hit", "age": "4"}, status=self.store[url])
        return FakeResponse("<clean/>", {"x-cache": "miss"}, status=200)


class UncachedRedirectSession:
    """The trigger header changes the response (a redirect) but NOTHING is cached:
    the clean follow-up reverts to baseline -> must NOT be flagged as persisted."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        headers = headers or {}
        if any(k.lower() == "x-forwarded-proto" for k in headers):
            return FakeResponse("", {"x-cache": "miss", "location": "https://evil.example/"}, status=301)
        return FakeResponse("<clean/>", {"x-cache": "miss"}, status=200)


class RateLimitOnPoisonSession:
    """The poison request trips a 429. Differential detection must treat 429 as
    rate-limit noise and NOT raise a finding from it."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        headers = headers or {}
        if any(k.lower() == "x-forwarded-proto" for k in headers):
            return FakeResponse("blocked", {"x-cache": "miss"}, status=429)
        return FakeResponse("<clean/>", {"x-cache": "miss"}, status=200)


class BodyPoisonCacheSession:
    """Non-reflective BODY poison: the trigger header swaps in a different (fixed,
    non-canary) body; the cache stores it; clean follow-ups get the poisoned body.
    Nothing is echoed, so only the body-diff path can catch it."""

    def __init__(self, trigger="X-Forwarded-Proto"):
        self.trigger = trigger.lower()
        self.store = {}

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        headers = headers or {}
        if any(k.lower() == self.trigger for k in headers):
            self.store[url] = "<maintenance/>"
            return FakeResponse("<maintenance/>", {"x-cache": "miss"}, status=200)
        if url in self.store:
            return FakeResponse(self.store[url], {"x-cache": "hit", "age": "3"}, status=200)
        return FakeResponse("<clean/>", {"x-cache": "miss"}, status=200)


class NoisyBodyLocationPoisonSession:
    """The body legitimately flaps every request (so body is untrusted), but a
    Location poison IS real and cached. The dimension-aware guard must still catch
    the location diff instead of bailing out on the body instability."""

    def __init__(self, trigger="X-Forwarded-Proto"):
        self.trigger = trigger.lower()
        self.store = {}
        self.n = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        self.n += 1
        headers = headers or {}
        if any(k.lower() == self.trigger for k in headers):
            self.store[url] = "https://evil.example/"
            return FakeResponse(f"<p {self.n}/>", {"x-cache": "miss", "location": "https://evil.example/"}, status=301)
        if url in self.store:
            return FakeResponse(f"<p {self.n}/>", {"x-cache": "hit", "age": "2", "location": self.store[url]}, status=301)
        return FakeResponse(f"<p {self.n}/>", {"x-cache": "miss"}, status=200)


class FatGetCacheSession:
    """Models fat-GET parameter cloaking: the origin merges GET *body* params and
    reflects the value; the cache keys on the URL only, so the poisoned body is stored
    under the bare URL and served back to a body-less (victim) request as a HIT."""

    def __init__(self, param="q"):
        self.param = param
        self.store = {}

    def get(self, url, headers=None, data=None, timeout=10, verify=True, allow_redirects=False):
        if data:
            from urllib.parse import parse_qs
            vals = parse_qs(data).get(self.param, [])
            if vals:
                body = f"<p>results for {vals[0]}</p>"
                self.store[url] = body
                return FakeResponse(body, {"x-cache": "miss"})
        if url in self.store:
            return FakeResponse(self.store[url], {"x-cache": "hit", "age": "9"})
        return FakeResponse("<p>results for </p>", {"x-cache": "miss"})


class MatrixParamCacheSession:
    """Models cache-key normalization abuse: the cache STRIPS a ;matrix path-param from
    its key while the origin still reads and reflects it. A poisoned ;utm_source= value
    is stored under the clean-path key and served to a victim requesting the clean path."""

    def __init__(self, param="utm_source"):
        self.param = param
        self.store = {}

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        # Parse the RAW url: urlparse() would hoist ;params into its .params field and
        # drop them from .path. Split on '#', then '?', then ';' by hand.
        no_frag = url.split("#", 1)[0]
        path_part, _, query_part = no_frag.partition("?")
        clean_path = path_part.split(";", 1)[0]
        matrix = ""
        for seg in path_part.split(";")[1:]:
            if seg.startswith(self.param + "="):
                matrix = seg.split("=", 1)[1]
        key = clean_path + ("?" + query_part if query_part else "")  # ;params stripped
        if matrix:
            body = f"<body>menu source: {matrix}</body>"
            self.store[key] = body
            return FakeResponse(body, {"x-cache": "miss"})
        if key in self.store:
            return FakeResponse(self.store[key], {"x-cache": "hit", "age": "7"})
        return FakeResponse("<body>menu source: direct</body>", {"x-cache": "miss"})


class _CachedOrigin:
    """A URL-keyed shared cache in front of an origin: the first request to a URL is a
    MISS that calls render() and stores the result, later ones are HITs of that copy.
    Request headers and body never enter the key (an unkeyed-input cache)."""

    def __init__(self):
        self.store = {}
        self.renders = 0

    def render(self, url, headers, data):  # pragma: no cover - overridden
        raise NotImplementedError

    def get(self, url, headers=None, data=None, timeout=10, verify=True, allow_redirects=False):
        if url in self.store:
            status, body = self.store[url]
            return FakeResponse(body, {"x-cache": "hit", "age": "3"}, status=status)
        self.renders += 1
        status, body = self.render(url, headers or {}, data)
        self.store[url] = (status, body)
        return FakeResponse(body, {"x-cache": "miss"}, status=status)


class TimeDriftSession(_CachedOrigin):
    """NOT vulnerable. The page embeds a token that rotates after the first
    `flip_after` origin renders (a timestamp/nonce bucket), so the baseline pair agrees
    and everything rendered later differs. Node 217734's real-world shape: a WordPress
    page behind Cloudflare whose body changed between the baselines and the poison."""

    def __init__(self, flip_after=2):
        super().__init__()
        self.flip_after = flip_after

    def render(self, url, headers, data):
        tick = 0 if self.renders <= self.flip_after else 1
        return 200, f"<html><body>archive tick={tick}</body></html>"


class PairedVariantSession(_CachedOrigin):
    """NOT vulnerable. A two-variant page (an A/B bucket picked per origin render) whose
    variants come in runs of two, so any two consecutive renders often agree."""

    def render(self, url, headers, data):
        return 200, f"<html><body>variant {'AB'[(self.renders // 2) % 2]}</body></html>"


class FlakyPoisonSession(_CachedOrigin):
    """NOT vulnerable. The origin fails ONCE (a 503 glitch) on exactly the render the
    poison request triggers; the cache stores that error for the poison slot."""

    def __init__(self, fail_on_render=3):
        super().__init__()
        self.fail_on_render = fail_on_render

    def render(self, url, headers, data):
        if self.renders == self.fail_on_render:
            return 503, "<h1>upstream error</h1>"
        return 200, "<html><body>article</body></html>"


class WafBlockSession(_CachedOrigin):
    """NOT vulnerable. A WAF in front of the cache blocks the scanner's IP as soon as it
    sees the trigger header, then answers EVERY request with an uncached 403."""

    def __init__(self, trigger="X-Forwarded-Proto"):
        super().__init__()
        self.trigger = trigger.lower()
        self.blocked = False

    def get(self, url, headers=None, data=None, **kwargs):
        if any(k.lower() == self.trigger for k in (headers or {})):
            self.blocked = True
        if self.blocked:
            return FakeResponse("<h1>Access denied</h1>", {}, status=403)
        return super().get(url, headers, data, **kwargs)

    def render(self, url, headers, data):
        return 200, "<html><body>article</body></html>"


class ScriptedVariantSession(_CachedOrigin):
    """NOT vulnerable. Origin renders cycle through the variants A A B A B B. Fed to one
    vector's own two-slot baseline, that sequence passes the baseline, the control and
    both reproductions; any 8 consecutive renders (the per-URL profile) see both."""

    def render(self, url, headers, data):
        return 200, f"<html><body>variant {'AABABB'[(self.renders - 1) % 6]}</body></html>"


class OriginStateSession:
    """NOT vulnerable, no cache in the path (silent: no cache headers). The origin
    remembers the last utm_source it saw for this client (what a cookie the session
    replays, or server-side attribution, does) and renders it into a hidden field."""

    def __init__(self):
        self.remembered = "direct"

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        from urllib.parse import parse_qs, urlparse
        vals = parse_qs(urlparse(url).query).get("utm_source")
        if vals:
            self.remembered = vals[0]
        return FakeResponse(f'<form><input type="hidden" name="utm_source" value="{self.remembered}"></form>')


class QueryIgnoringCacheSession:
    """A cache whose key ignores the query string entirely (a CDN "ignore query string"
    rule) in front of an origin that reflects X-Forwarded-Host. Records how many
    requests carried the trigger header, i.e. how many reached the REAL entry."""

    def __init__(self):
        self.store = {}
        self.poison_requests = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        from urllib.parse import urlparse
        key = urlparse(url).path
        xfh = (headers or {}).get("X-Forwarded-Host")
        if xfh:
            self.poison_requests += 1
        if key in self.store:
            return FakeResponse(self.store[key], {"x-cache": "hit", "age": "5"})
        body = f"<link href=//{xfh or 'cdn.shop'}/s.css>"
        self.store[key] = body
        return FakeResponse(body, {"x-cache": "miss"})


class TestWcvsParser(unittest.TestCase):
    """The WCVS JSON report parser (pkg/report.go schema)."""

    def _write_report(self, payload: dict) -> str:
        fd, path = tempfile.mkstemp(suffix="_Report.json")
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        return path

    def test_extracts_only_vulnerable(self):
        report = {
            "foundVulnerabilities": True,
            "websites": [
                {
                    "url": "https://shop/home", "isVulnerable": True,
                    "cacheIndicator": "X-Cache", "cacheBusterFound": True, "cacheBuster": "utm",
                    "results": [
                        {"technique": "Header Poisoning", "isVulnerable": True, "checks": [
                            {"identifier": "X-Forwarded-Host", "reason": "reflected+cached",
                             "reflections": ["//CANARY/"], "request": {"curlCommand": "curl ..."}}]},
                        {"technique": "Header Poisoning", "isVulnerable": False, "checks": []},
                    ],
                },
                {"url": "https://shop/safe", "isVulnerable": False, "results": []},
            ],
        }
        path = self._write_report(report)
        try:
            candidates = wcvs_runner.parse_wcvs_report(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(candidates), 1)
        c = candidates[0]
        self.assertEqual(c["url"], "https://shop/home")
        self.assertEqual(c["vector_name"], "X-Forwarded-Host")
        self.assertEqual(c["cache_indicator"], "X-Cache")
        self.assertTrue(c["cache_buster_found"])
        self.assertEqual(c["source"], "wcvs")

    def test_bad_report_returns_empty(self):
        fd, path = tempfile.mkstemp(suffix="_Report.json")
        with os.fdopen(fd, "w") as f:
            f.write("not json")
        try:
            self.assertEqual(wcvs_runner.parse_wcvs_report(path), [])
        finally:
            os.unlink(path)

    def test_safety_skip_tests(self):
        # deception + cpdos disallowed -> both technique groups skipped
        skip = wcvs_runner.safety_skip_tests(allow_deception=False, allow_cpdos=False)
        self.assertIn("deception", skip)
        self.assertIn("dos", skip)
        # both allowed -> nothing skipped
        self.assertEqual(wcvs_runner.safety_skip_tests(True, True), [])

    def test_command_isolation_flags(self):
        cmd = wcvs_runner.build_wcvs_command(
            "/tmp/redamon/x/targets.txt", "/tmp/redamon/x", "redamon-wcvs:latest",
            threads=8, skip_timebased=True, skip_tests=["dos"])
        self.assertIn("--net=host", cmd)
        self.assertIn("-gr", cmd)
        self.assertIn("-stime", cmd)
        self.assertIn("redamon-wcvs:latest", cmd)
        self.assertIn("-st", cmd)

    def test_command_rate_and_cache_header_flags(self):
        cmd = wcvs_runner.build_wcvs_command(
            "/t/targets.txt", "/t", "img", req_rate=5.0, cache_header="X-Custom-CB")
        self.assertIn("-rr", cmd)
        self.assertIn("5.0", cmd)
        self.assertIn("-ch", cmd)
        self.assertIn("X-Custom-CB", cmd)

    def test_command_no_rate_flag_when_zero(self):
        cmd = wcvs_runner.build_wcvs_command("/t/targets.txt", "/t", "img", req_rate=0)
        self.assertNotIn("-rr", cmd)

    def test_command_threads_clamped_to_min_one(self):
        cmd = wcvs_runner.build_wcvs_command("/t/targets.txt", "/t", "img", threads=0)
        i = cmd.index("-t")
        self.assertEqual(cmd[i + 1], "1")

    def test_skiptest_skip_timebased_off(self):
        cmd = wcvs_runner.build_wcvs_command("/t/targets.txt", "/t", "img", skip_timebased=False)
        self.assertNotIn("-stime", cmd)

    def test_safety_skip_deception_only(self):
        skip = wcvs_runner.safety_skip_tests(allow_deception=False, allow_cpdos=True)
        self.assertIn("deception", skip)
        self.assertIn("css", skip)
        self.assertNotIn("dos", skip)

    def test_safety_skip_cpdos_only(self):
        skip = wcvs_runner.safety_skip_tests(allow_deception=True, allow_cpdos=False)
        self.assertEqual(skip, ["dos"])

    def test_run_wcvs_empty_targets_no_docker(self):
        # No targets -> short-circuit to [] without ever invoking docker.
        self.assertEqual(wcvs_runner.run_wcvs([], {}), [])

    def test_parse_flattens_multiple_checks(self):
        report = {"websites": [{"url": "https://s/a", "isVulnerable": True, "results": [
            {"technique": "Header Poisoning", "isVulnerable": True, "checks": [
                {"identifier": "X-Forwarded-Host", "reason": "r1"},
                {"identifier": "X-Forwarded-Scheme", "reason": "r2"}]}]}]}
        path = self._write_report(report)
        try:
            cands = wcvs_runner.parse_wcvs_report(path)
        finally:
            os.unlink(path)
        self.assertEqual({c["vector_name"] for c in cands}, {"X-Forwarded-Host", "X-Forwarded-Scheme"})

    def test_parse_skips_non_vulnerable_result_within_vulnerable_site(self):
        report = {"websites": [{"url": "https://s/a", "isVulnerable": True, "results": [
            {"technique": "A", "isVulnerable": False, "checks": [{"identifier": "X-A"}]},
            {"technique": "B", "isVulnerable": True, "checks": [{"identifier": "X-B"}]}]}]}
        path = self._write_report(report)
        try:
            cands = wcvs_runner.parse_wcvs_report(path)
        finally:
            os.unlink(path)
        self.assertEqual([c["vector_name"] for c in cands], ["X-B"])

    def test_parse_missing_report_file_returns_empty(self):
        self.assertEqual(wcvs_runner.parse_wcvs_report("/no/such/file_Report.json"), [])


class TestScoring(unittest.TestCase):
    def test_confirmed(self):
        conf, tier = scoring.score_finding({
            "reflected_in_baseline": True, "persisted_on_clean": True,
            "cache_hit_on_clean": True, "repeated_ok": True, "stable": True})
        self.assertEqual(tier, "Confirmed")
        self.assertGreaterEqual(conf, 0.95)

    def test_strong_without_repeat(self):
        conf, tier = scoring.score_finding({
            "persisted_on_clean": True, "cache_hit_on_clean": True, "stable": True})
        self.assertEqual(tier, "Strong")

    def test_differential_only_capped_at_strong(self):
        # All Confirmed-grade signals present, but persistence was non-reflective.
        conf, tier = scoring.score_finding({
            "reflected_in_baseline": False, "persisted_on_clean": True,
            "persisted_reflected": False, "persisted_differential": True,
            "cache_hit_on_clean": True, "repeated_ok": True, "stable": True})
        self.assertEqual(tier, "Strong")
        self.assertLess(conf, 0.95)

    def test_reflected_but_not_persisted_rejected(self):
        conf, tier = scoring.score_finding({
            "reflected_in_baseline": True, "persisted_on_clean": False})
        self.assertEqual(tier, "Rejected")
        self.assertLess(conf, 0.5)

    def test_min_confidence_gate(self):
        self.assertTrue(scoring.passes_min_confidence(0.97, {"WEB_CACHE_POISON_MIN_CONFIDENCE": 0.8}))
        self.assertFalse(scoring.passes_min_confidence(0.65, {"WEB_CACHE_POISON_MIN_CONFIDENCE": 0.8}))

    def test_tentative_when_persisted_but_unstable(self):
        conf, tier = scoring.score_finding({
            "persisted_on_clean": True, "cache_hit_on_clean": False, "stable": False})
        self.assertEqual(tier, "Tentative")
        self.assertTrue(0.5 <= conf < 0.8)

    def test_not_persisted_not_reflected_hard_rejected(self):
        conf, tier = scoring.score_finding({"persisted_on_clean": False, "reflected_in_baseline": False})
        self.assertEqual(tier, "Rejected")
        self.assertLessEqual(conf, 0.1)

    def test_severity_mapping(self):
        self.assertEqual(scoring.severity_for_impact("stored_xss")[0], "critical")
        self.assertEqual(scoring.severity_for_impact("open_redirect")[0], "high")

    def test_severity_table_full(self):
        for impact, sev in [("stored_xss", "critical"), ("open_redirect", "high"),
                            ("deception", "high"), ("dos", "high"), ("reflected", "medium"),
                            ("unknown", "medium")]:
            s, cvss = scoring.severity_for_impact(impact)
            self.assertEqual(s, sev)
            self.assertGreater(cvss, 0)
        # Unrecognised impact falls back to medium, not a crash.
        self.assertEqual(scoring.severity_for_impact("nonsense")[0], "medium")
        self.assertEqual(scoring.severity_for_impact("")[0], "medium")

    def test_min_confidence_gate_custom_threshold(self):
        self.assertTrue(scoring.passes_min_confidence(0.82, {"WEB_CACHE_POISON_MIN_CONFIDENCE": 0.8}))
        self.assertFalse(scoring.passes_min_confidence(0.82, {"WEB_CACHE_POISON_MIN_CONFIDENCE": 0.9}))
        # Default threshold (0.8) applies when unset.
        self.assertFalse(scoring.passes_min_confidence(0.65, {}))


class TestSafety(unittest.TestCase):
    def test_canary_host_non_resolving(self):
        token = safety.new_canary_token()
        self.assertTrue(safety.canary_host(token).endswith(".invalid"))

    def test_cpdos_requires_research_profile(self):
        self.assertFalse(safety.is_cpdos_allowed(
            {"WEB_CACHE_POISON_SCAN_PROFILE": "safe-confirm", "WEB_CACHE_POISON_ALLOW_CPDOS": True}))
        self.assertTrue(safety.is_cpdos_allowed(
            {"WEB_CACHE_POISON_SCAN_PROFILE": "research", "WEB_CACHE_POISON_ALLOW_CPDOS": True}))

    def test_cpdos_research_profile_alone_insufficient(self):
        # Research profile but toggle off -> still blocked (needs BOTH).
        self.assertFalse(safety.is_cpdos_allowed({"WEB_CACHE_POISON_SCAN_PROFILE": "research"}))
        # Toggle on but extended profile -> blocked.
        self.assertFalse(safety.is_cpdos_allowed(
            {"WEB_CACHE_POISON_SCAN_PROFILE": "extended", "WEB_CACHE_POISON_ALLOW_CPDOS": True}))

    def test_cpdos_default_blocked(self):
        self.assertFalse(safety.is_cpdos_allowed({}))

    def test_deception_default_allowed_and_toggle(self):
        self.assertTrue(safety.is_deception_allowed({}))
        self.assertFalse(safety.is_deception_allowed({"WEB_CACHE_POISON_ALLOW_DECEPTION": False}))

    def test_framework_packs_default_allowed_and_toggle(self):
        self.assertTrue(safety.is_framework_packs_allowed({}))
        self.assertFalse(safety.is_framework_packs_allowed({"WEB_CACHE_POISON_ALLOW_FRAMEWORK_PACKS": False}))

    def test_canary_token_and_value_format(self):
        tok = safety.new_canary_token()
        self.assertTrue(tok.startswith("rdmn"))
        self.assertEqual(safety.canary_value(tok), tok)  # plain marker for param/value vectors
        self.assertTrue(safety.canary_host(tok).startswith(tok + "."))

    def test_cache_buster_values_unique(self):
        vals = {safety.new_cache_buster_value() for _ in range(200)}
        self.assertEqual(len(vals), 200)  # no collisions across many mints
        self.assertTrue(all(v.startswith("cb") for v in vals))


class TestHypotheses(unittest.TestCase):
    def test_generic_headers_always_present(self):
        h = hypotheses.generate_hypotheses("https://x/", {}, {}, set())
        names = {v["vector_name"] for v in h}
        self.assertIn("X-Forwarded-Host", names)

    def test_framework_pack_gated_on_fingerprint(self):
        combined = {"http_probe": {"technologies_found": {"Next.js": 3}}}
        h = hypotheses.generate_hypotheses("https://x/", combined,
                                           {"WEB_CACHE_POISON_ALLOW_FRAMEWORK_PACKS": True}, set())
        names = {v["vector_name"] for v in h}
        self.assertIn("x-invoke-status", names)
        # No Next.js fingerprint -> no Next pack
        h2 = hypotheses.generate_hypotheses("https://x/", {},
                                            {"WEB_CACHE_POISON_ALLOW_FRAMEWORK_PACKS": True}, set())
        self.assertNotIn("x-invoke-status", {v["vector_name"] for v in h2})

    def test_skips_wcvs_seen_vectors(self):
        h = hypotheses.generate_hypotheses("https://x/", {}, {}, {"X-Forwarded-Host"})
        self.assertNotIn("X-Forwarded-Host", {v["vector_name"] for v in h})

    def test_expanded_pack_includes_non_reflective_headers(self):
        h = hypotheses.generate_hypotheses("https://x/", {}, {}, set())
        names = {v["vector_name"] for v in h}
        # Headers that were previously missing (ported from CacheX).
        for expected in ("X-Forwarded-Port", "Forwarded", "True-Client-IP", "X-Original-Host"):
            self.assertIn(expected, names)

    def test_includes_unkeyed_param_vectors(self):
        h = hypotheses.generate_hypotheses("https://x/", {}, {}, set())
        params = {v["vector_name"] for v in h if v.get("vector_type") == "param"}
        self.assertIn("utm_source", params)
        self.assertIn("callback", params)
        # param vectors are the param-cloaking technique
        self.assertTrue(all(v["technique"] == "unkeyed_param"
                            for v in h if v.get("vector_type") == "param"))

    def test_fixed_payload_kinds_carry_safe_values(self):
        self.assertEqual(confirm._payload_value("scheme", "tok"), "https")
        self.assertEqual(confirm._payload_value("port", "tok"), "443")
        self.assertEqual(confirm._payload_value("ip", "tok"), "127.0.0.1")
        # Host stays a benign non-resolving canary, never CacheX's evil.com.
        self.assertTrue(confirm._payload_value("host", "tok").endswith(".redamon-poc.invalid"))
        self.assertIn(".redamon-poc.invalid", confirm._payload_value("forwarded", "tok"))


class TestBuster(unittest.TestCase):
    def test_add_cache_buster_preserves_query(self):
        out = buster.add_cache_buster("https://x/home?lang=en", "cb", "abc")
        self.assertIn("lang=en", out)
        self.assertIn("cb=abc", out)

    def test_add_cache_buster_no_existing_query(self):
        out = buster.add_cache_buster("https://x/home", "cb", "abc")
        self.assertTrue(out.endswith("?cb=abc"))

    def test_add_cache_buster_overwrites_same_param(self):
        out = buster.add_cache_buster("https://x/home?cb=old", "cb", "new")
        self.assertIn("cb=new", out)
        self.assertNotIn("cb=old", out)

    def test_add_cache_buster_preserves_path_and_scheme(self):
        out = buster.add_cache_buster("http://x:8080/a/b", "cb", "1")
        self.assertTrue(out.startswith("http://x:8080/a/b?"))

    def test_add_path_segment_before_query(self):
        # Segment lands as a real path element, query (the buster) preserved after it.
        out = buster.add_path_segment("https://x/fw/nuxt?rdmncb=1", "_payload.json")
        self.assertEqual(out, "https://x/fw/nuxt/_payload.json?rdmncb=1")

    def test_add_path_segment_no_query_and_trailing_slash(self):
        self.assertEqual(buster.add_path_segment("https://x/a", "b"), "https://x/a/b")
        self.assertEqual(buster.add_path_segment("https://x/a/", "/b"), "https://x/a/b")

    def test_find_buster_default_param_and_isolated_on_miss(self):
        info = buster.find_cache_buster("https://x/", _HeaderSession({"x-cache": "miss"}), {})
        self.assertEqual(info["param"], "rdmncb")
        self.assertTrue(info["isolated"])

    def test_find_buster_ignores_a_retried_5xx_hit(self):
        # The origin flaked on the first probe; the session's retry re-sent it onto the
        # slot that 503 had just filled and came back a HIT. Seen on the lab's
        # /safe/flaky, which was then skipped as "cache ignores the query string".
        class _FlakyFirstProbe:
            def __init__(self):
                self.calls = 0

            def get(self, url, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    return FakeResponse("<h1>503</h1>", {"x-cache": "HIT"}, status=503)
                return FakeResponse("<ok/>", {"x-cache": "MISS" if self.calls == 2 else "HIT"})

        info = buster.find_cache_buster("https://x/", _FlakyFirstProbe(), {})
        self.assertTrue(info["isolated"])
        self.assertTrue(info["keyed_on_query"])

    def test_find_buster_hit_on_a_fresh_value_is_not_isolated(self):
        # A never-used buster value can only HIT if the cache ignores the query string:
        # every "isolated" test slot would be the entry real visitors get.
        sess = _SeqSession([{"x-cache": "hit"}, {"x-cache": "hit"}])
        info = buster.find_cache_buster("https://x/", sess, {})
        self.assertFalse(info["isolated"])
        self.assertFalse(info["keyed_on_query"])

    def test_find_buster_custom_param_from_settings(self):
        info = buster.find_cache_buster(
            "https://x/", _HeaderSession({"x-cache": "hit"}),
            {"WEB_CACHE_POISON_CACHE_BUSTER_PARAM": "zzz"})
        self.assertEqual(info["param"], "zzz")

    def test_find_buster_detects_query_keying_on_hit(self):
        # miss then hit on the busted URL -> query string participates in the key.
        sess = _SeqSession([{"x-cache": "miss"}, {"x-cache": "hit"}])
        info = buster.find_cache_buster("https://x/", sess, {})
        self.assertTrue(info["keyed_on_query"])

    def test_find_buster_unknown_state_not_keyed(self):
        # No cache headers at all -> cannot conclude the query is keyed.
        info = buster.find_cache_buster("https://x/", _HeaderSession({}), {})
        self.assertFalse(info["keyed_on_query"])

    def test_find_buster_network_error_is_safe(self):
        info = buster.find_cache_buster("https://x/", _RaisingSession(), {})
        self.assertFalse(info["keyed_on_query"])
        self.assertTrue(info["isolated"])  # still safe to isolate

    def test_find_buster_uses_fresh_value_each_call(self):
        # Two calls must mint different cache-buster values (per-test isolation).
        seen = set()
        for _ in range(5):
            sess = _SeqSession([{"x-cache": "miss"}])
            buster.find_cache_buster("https://x/", sess, {})
            # the value is internal; assert via add_cache_buster determinism instead
        v1, v2 = safety.new_cache_buster_value(), safety.new_cache_buster_value()
        self.assertNotEqual(v1, v2)


class TestNormalizers(unittest.TestCase):
    def test_build_finding_maps_vector(self):
        vec = {"url": "https://x/home", "technique": "unkeyed_header",
               "vector_type": "header", "vector_name": "X-Forwarded-Host", "source": "wcvs"}
        conf = {"evidence": {"poc_link": "https://x/home?cb=1", "cache_buster": "cb=1"}}
        f = normalizers.build_finding(vec, conf, 0.97, "Confirmed", "open_redirect", "high", 7.4, ["x-cache: hit"])
        self.assertEqual(f["cache_header"], "X-Forwarded-Host")
        self.assertEqual(f["cache_param"], "")
        self.assertEqual(f["confidence_tier"], "Confirmed")

    def test_build_finding_param_vector_sets_cache_param(self):
        vec = {"url": "https://x/?q=1", "technique": "unkeyed_param",
               "vector_type": "param", "vector_name": "utm_source", "source": "wcvs"}
        f = normalizers.build_finding(vec, {"evidence": {}}, 0.9, "Strong", "reflected", "medium", 5.3, [])
        self.assertEqual(f["cache_param"], "utm_source")
        self.assertEqual(f["cache_header"], "")  # param vectors leave the header field empty

    def test_build_finding_evidence_is_whitelisted(self):
        # Stray confirmation evidence keys must NOT leak into the finding (graph contract).
        conf = {"evidence": {"poc_link": "p", "secret_internal": "LEAK", "differential_change": "status"}}
        vec = {"url": "https://x/", "vector_type": "header", "vector_name": "X-Host"}
        f = normalizers.build_finding(vec, conf, 0.9, "Strong", "open_redirect", "high", 7.4, [])
        self.assertNotIn("secret_internal", f["evidence"])
        self.assertEqual(f["evidence"]["differential_change"], "status")

    def test_summary_counts(self):
        f1 = {"confidence_tier": "Confirmed", "impact": "stored_xss", "severity": "critical"}
        f2 = {"confidence_tier": "Strong", "impact": "open_redirect", "severity": "high"}
        res = normalizers.build_cache_scan_result({"total_urls_scanned": 5, "cacheable_urls": 2}, {}, [f1, f2])
        self.assertEqual(res["summary"]["total_findings"], 2)
        self.assertEqual(res["summary"]["confirmed"], 1)
        self.assertEqual(res["summary"]["strong"], 1)
        self.assertEqual(res["summary"]["by_impact"]["stored_xss"], 1)

    def test_summary_aggregates_severity_and_tiers(self):
        findings = [
            {"confidence_tier": "Confirmed", "impact": "open_redirect", "severity": "high"},
            {"confidence_tier": "Strong", "impact": "open_redirect", "severity": "high"},
            {"confidence_tier": "Tentative", "impact": "dos", "severity": "high"},
        ]
        res = normalizers.build_cache_scan_result({"total_urls_scanned": 9, "cacheable_urls": 4}, {}, findings)
        s = res["summary"]
        self.assertEqual(s["by_severity"]["high"], 3)
        self.assertEqual(s["by_impact"]["open_redirect"], 2)
        self.assertEqual(s["tentative"], 1)
        self.assertEqual(s["urls_scanned"], 9)
        self.assertEqual(s["cacheable_urls"], 4)

    def test_empty_findings_summary_is_zeroed(self):
        res = normalizers.build_cache_scan_result({"total_urls_scanned": 0, "cacheable_urls": 0}, {}, [])
        self.assertEqual(res["summary"]["total_findings"], 0)
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["by_target"], {})


class _HeaderSession:
    """Returns a fixed set of response headers on every GET."""

    def __init__(self, headers, body="<x/>"):
        self._headers = headers
        self._body = body

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        return FakeResponse(self._body, dict(self._headers))


class _FrozenDateSession:
    """Silent cache: no cache headers, but the Date is frozen (cached replay)."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        return FakeResponse("<cached/>", {"date": "Mon, 30 Jun 2026 10:00:00 GMT"})


class _LiveOriginSession:
    """Live origin: no cache headers and the Date advances every request."""

    def __init__(self):
        self._n = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        self._n += 1
        return FakeResponse("<dynamic/>", {"date": f"Mon, 30 Jun 2026 10:00:0{self._n} GMT"})


_NO_SLEEP = lambda *_: None


class _SeqSession:
    """Returns a scripted sequence of response-header dicts across GETs; the last
    entry repeats once exhausted. Records how many GETs were issued."""

    def __init__(self, header_steps, body="<x/>"):
        self._steps = header_steps
        self._body = body
        self.calls = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        hdrs = self._steps[min(self.calls, len(self._steps) - 1)]
        self.calls += 1
        return FakeResponse(self._body, dict(hdrs))


class _RaisingSession:
    """Every GET raises a network error (timeouts, connection resets)."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        raise requests.RequestException("boom")


class TestOracle(unittest.TestCase):
    def test_cacheable_detected_from_x_cache(self):
        info = oracle.detect_cache_oracle("https://x/", SafeCacheSession())
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_not_cacheable_when_no_signals(self):
        info = oracle.detect_cache_oracle("https://x/", NoCacheSession(), behavioral=False)
        self.assertFalse(info["cacheable"])

    def test_via_header_presence_detects_cache(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"via": "1.1 varnish"}))
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["cache_layer"])

    def test_varnish_numeric_two_ids_is_hit(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"x-varnish": "1001 2002"}))
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_nginx_stale_status_is_cacheable(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"x-cache-status": "STALE"}))
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_cloudflare_dynamic_is_not_cacheable(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cf-cache-status": "DYNAMIC"}), behavioral=False
        )
        self.assertFalse(info["cacheable"])
        self.assertTrue(info["cache_layer"])  # CDN present, just not caching this URL

    def test_cache_control_public_makes_eligible(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "public, max-age=600"})
        )
        self.assertTrue(info["cacheable"])

    def test_cache_control_no_store_not_cacheable(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "private, no-store, max-age=600"}),
            behavioral=False,
        )
        self.assertFalse(info["cacheable"])

    def test_vary_header_captured(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"x-cache": "hit", "vary": "X-Forwarded-Host"})
        )
        self.assertEqual(info["vary"], "X-Forwarded-Host")

    def test_behavioral_frozen_date_detects_silent_cache(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _FrozenDateSession(), behavioral=True, sleep_fn=_NO_SLEEP
        )
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["behavioral"])
        self.assertEqual(info["indicator"], "behavioral:frozen-date")

    def test_behavioral_live_origin_not_cacheable(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _LiveOriginSession(), behavioral=True, sleep_fn=_NO_SLEEP
        )
        self.assertFalse(info["cacheable"])
        self.assertFalse(info["behavioral"])

    def test_response_cache_state(self):
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"x-cache": "HIT"})), "hit")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"x-cache": "MISS"})), "miss")
        # Age: 0 is ambiguous (a same-second hit), and scoring rejects an explicit miss.
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"age": "0"})), "unknown")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={})), "unknown")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"x-cache-status": "STALE"})), "hit")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"x-varnish": "1001 2002"})), "hit")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"x-varnish": "1001"})), "miss")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"cf-cache-status": "DYNAMIC"})), "miss")

    def test_age_zero_cacheable_but_not_a_hit(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"age": "0"}), behavioral=False)
        self.assertTrue(info["cacheable"])
        self.assertFalse(info["saw_hit"])

    def test_age_positive_is_a_hit(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"age": "42"}), behavioral=False)
        self.assertTrue(info["saw_hit"])

    def test_age_non_numeric_is_graceful(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"age": "garbage"}), behavioral=False)
        self.assertTrue(info["cacheable"])  # age header present -> cache layer
        self.assertFalse(info["saw_hit"])

    def test_cache_control_no_store_overrides_public(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "public, no-store"}), behavioral=False)
        self.assertFalse(info["cacheable"])

    def test_cache_control_private_disqualifies(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "private, max-age=600"}), behavioral=False)
        self.assertFalse(info["cacheable"])

    def test_status_miss_does_not_override_a_private_response(self):
        # nginx stamps X-Cache-Status: MISS on every proxied response, stored or not;
        # the lab's /oracle/no-store and /oracle/cf-dynamic were scanned because of it.
        for hdrs in ({"x-cache-status": "MISS", "cache-control": "no-store, private"},
                     {"x-cache-status": "MISS", "cf-cache-status": "DYNAMIC",
                      "cache-control": "private, no-cache"}):
            info = oracle.detect_cache_oracle("https://x/", _HeaderSession(hdrs), behavioral=False)
            self.assertFalse(info["cacheable"], hdrs)
            self.assertTrue(info["cache_layer"])

    def test_private_page_whose_hit_shows_on_the_third_probe_stays_cacheable(self):
        # A multi-node edge: the first two probes land on cold nodes.
        sess = _SeqSession([{"x-cache": "MISS", "cache-control": "private"},
                            {"x-cache": "MISS", "cache-control": "private"},
                            {"x-cache": "HIT", "cache-control": "private"}])
        info = oracle.detect_cache_oracle("https://x/", sess, behavioral=False)
        self.assertTrue(info["cacheable"])
        self.assertEqual(sess.calls, 3)

    def test_private_page_a_cache_stores_anyway_stays_cacheable(self):
        # An edge rule that caches despite the origin's directive shows a HIT on repeat.
        sess = _SeqSession([{"x-cache": "MISS", "cache-control": "private"},
                            {"x-cache": "HIT", "cache-control": "private"}])
        info = oracle.detect_cache_oracle("https://x/", sess, behavioral=False)
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_s_maxage_makes_eligible(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "s-maxage=300"}), behavioral=False)
        self.assertTrue(info["cacheable"])

    def test_max_age_zero_not_eligible(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "max-age=0"}), behavioral=False)
        self.assertFalse(info["cacheable"])

    def test_presence_via_header_marks_cache_layer(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"via": "1.1 varnish"}), behavioral=False)
        self.assertTrue(info["cache_layer"])
        self.assertTrue(info["cacheable"])

    def test_behavioral_no_date_cannot_infer(self):
        # Silent cache with no Date header -> frozen-date probe can't conclude.
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({}), behavioral=True, sleep_fn=_NO_SLEEP)
        self.assertFalse(info["cacheable"])

    def test_behavioral_frozen_date_but_body_changes_not_cached(self):
        class _FrozenDateLiveBody:
            def __init__(self): self.n = 0
            def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
                self.n += 1
                return FakeResponse(f"<b {self.n}/>", {"date": "Mon, 30 Jun 2026 10:00:00 GMT"})
        info = oracle.detect_cache_oracle(
            "https://x/", _FrozenDateLiveBody(), behavioral=True, sleep_fn=_NO_SLEEP)
        self.assertFalse(info["cacheable"])  # date frozen but body differs -> not a replay

    def test_oracle_network_error_returns_safe_structure(self):
        info = oracle.detect_cache_oracle("https://x/", _RaisingSession())
        self.assertFalse(info["cacheable"])
        self.assertFalse(info["cache_layer"])
        self.assertTrue(any("error" in s for s in info["signals"]))


class TestConfirm(unittest.TestCase):
    def _vector(self):
        return {"url": "https://shop/home", "vector_type": "header",
                "vector_name": "X-Forwarded-Host", "payload_kind": "host",
                "impact_hint": "open_redirect"}

    def test_vulnerable_cache_confirms(self):
        session = VulnerableCacheSession("X-Forwarded-Host")
        rec = confirm.confirm_vector(self._vector(), {"param": "cb"}, session, {})
        self.assertTrue(rec["reflected_in_baseline"])
        self.assertTrue(rec["persisted_on_clean"])
        self.assertTrue(rec["cache_hit_on_clean"])
        conf, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Confirmed")
        self.assertGreaterEqual(conf, 0.95)
        self.assertTrue(rec["evidence"]["poc_link"])

    def test_safe_cache_rejected(self):
        session = SafeCacheSession()
        rec = confirm.confirm_vector(self._vector(), {"param": "cb"}, session, {})
        self.assertFalse(rec["persisted_on_clean"])
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Rejected")

    def _diff_vector(self):
        return {"url": "https://shop/login", "vector_type": "header",
                "vector_name": "X-Forwarded-Proto", "payload_kind": "scheme",
                "impact_hint": "open_redirect"}

    def test_non_reflective_poisoning_confirmed_as_strong(self):
        # No marker is echoed; only the differential (Location) detector catches it.
        session = DifferentialCacheSession("X-Forwarded-Proto")
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertFalse(rec["reflected_in_baseline"])
        self.assertTrue(rec["persisted_differential"])
        self.assertTrue(rec["persisted_on_clean"])
        self.assertEqual(rec["differential_change"], "location")
        self.assertEqual(rec["detection_mode"], "differential")
        conf, tier = scoring.score_finding(rec)
        # Differential-only persistence is capped at Strong (never Confirmed).
        self.assertEqual(tier, "Strong")
        self.assertLess(conf, 0.95)
        # A fixed "https" payload cannot choose where the redirect goes, so the cached
        # redirect is a behaviour change, not an open redirect.
        self.assertEqual(confirm.classify_impact(self._diff_vector(), rec), "response_change")

    def test_dynamic_page_no_false_positive(self):
        # Body flaps every request -> body dimension untrusted -> no differential finding.
        session = DynamicNoiseSession()
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertFalse(rec["baseline_stable"])
        self.assertFalse(rec["persisted_differential"])
        self.assertFalse(rec["persisted_on_clean"])
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Rejected")

    def test_differential_disabled_falls_back_to_reflected(self):
        session = DifferentialCacheSession("X-Forwarded-Proto")
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session,
                                     {"WEB_CACHE_POISON_DIFFERENTIAL": False})
        # With differential off, the non-reflective poison is invisible.
        self.assertEqual(rec["differential_change"], "")
        self.assertFalse(rec["persisted_on_clean"])

    def test_persisted_status_change_classified_as_dos(self):
        session = StatusPoisonCacheSession("X-Forwarded-Proto")
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertEqual(rec["differential_change"], "status")
        self.assertTrue(rec["persisted_differential"])
        self.assertEqual(confirm.classify_impact(self._diff_vector(), rec), "dos")
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Strong")

    def test_change_that_reverts_is_not_persisted(self):
        session = UncachedRedirectSession()
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        # The poison changed the response, but the clean follow-up reverted (uncached).
        self.assertEqual(rec["differential_change"], "location")
        self.assertFalse(rec["persisted_differential"])
        self.assertFalse(rec["persisted_on_clean"])
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Rejected")

    def test_429_on_poison_suppresses_differential(self):
        session = RateLimitOnPoisonSession()
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertEqual(rec["differential_change"], "")
        self.assertFalse(rec["persisted_on_clean"])

    def test_pure_body_diff_poisoning_detected(self):
        session = BodyPoisonCacheSession("X-Forwarded-Proto")
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertFalse(rec["reflected_in_baseline"])
        self.assertEqual(rec["differential_change"], "body")
        self.assertTrue(rec["persisted_differential"])
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Strong")

    def test_dimension_aware_guard_catches_location_despite_noisy_body(self):
        # Body is untrusted (flaps), but a real Location poison must still be found.
        session = NoisyBodyLocationPoisonSession("X-Forwarded-Proto")
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertFalse(rec["baseline_stable"])          # body made baseline unstable
        self.assertEqual(rec["differential_change"], "location")  # ...but location was trusted
        self.assertTrue(rec["persisted_differential"])
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Strong")

    def test_apply_vector_header(self):
        url, hdrs, body = confirm._apply_vector("https://x/p", "header", "X-Forwarded-Host", "evil.invalid")
        self.assertEqual(url, "https://x/p")
        self.assertEqual(hdrs, {"X-Forwarded-Host": "evil.invalid"})
        self.assertIsNone(body)

    def test_apply_vector_param(self):
        url, hdrs, body = confirm._apply_vector("https://x/p", "param", "utm", "evil")
        self.assertIn("utm=evil", url)
        self.assertEqual(hdrs, {})
        self.assertIsNone(body)

    def test_apply_vector_path_uses_vector_name_before_query(self):
        # Nuxt vector: ("_payload.json", "path", "path", "reflected"). The confusion
        # suffix must land as a real path segment BEFORE the cache-buster query, and
        # must be the vector NAME, not the random canary payload (the old bug appended
        # the payload after "?rdmncb=", so "_payload.json" was never exercised).
        url, hdrs, body = confirm._apply_vector(
            "https://x/fw/nuxt?rdmncb=abc123", "path", "_payload.json", "/rdmncanary")
        self.assertEqual(url, "https://x/fw/nuxt/_payload.json?rdmncb=abc123")
        self.assertNotIn("rdmncanary", url)       # random payload not used for path
        self.assertEqual(hdrs, {})
        self.assertIsNone(body)

    def test_apply_vector_fat_get_puts_param_in_body_not_url(self):
        # Fat GET: the param rides in the request BODY, the URL stays clean (so a
        # URL-keyed cache never sees it), with a form content-type set.
        url, hdrs, body = confirm._apply_vector("https://x/p", "fat_get", "q", "rdmncanary")
        self.assertEqual(url, "https://x/p")            # URL untouched
        self.assertEqual(body, "q=rdmncanary")          # param in the body
        self.assertEqual(hdrs.get("Content-Type"), "application/x-www-form-urlencoded")

    def test_apply_vector_path_param_matrix_before_query(self):
        # Normalization vector: the payload rides as a ;matrix path-param, appended to
        # the PATH before the query (a cache that strips ;params from its key is then
        # poisonable). No headers, no body.
        url, hdrs, body = confirm._apply_vector(
            "https://x/normalize/menu?rdmncb=abc", "path_param", "utm_source", "rdmnwin")
        self.assertEqual(url, "https://x/normalize/menu;utm_source=rdmnwin?rdmncb=abc")
        self.assertEqual(hdrs, {})
        self.assertIsNone(body)

    def test_path_param_confirmation_reflected_and_cached(self):
        # Confirmation against a fake cache that strips ;params from the key while the
        # origin reads them: the ;-param canary is served from cache to the clean victim.
        vec = {"url": "https://shop/normalize/menu", "vector_type": "path_param",
               "vector_name": "utm_source", "payload_kind": "value", "impact_hint": "reflected"}
        rec = confirm.confirm_vector(vec, {"param": "rdmncb"}, MatrixParamCacheSession("utm_source"), {})
        self.assertTrue(rec["reflected_in_baseline"])
        self.assertTrue(rec["persisted_on_clean"])
        self.assertTrue(rec["cache_hit_on_clean"])

    def test_fat_get_confirmation_reflected_and_cached(self):
        # End-to-end confirmation against a fat-GET-vulnerable fake cache: the canary
        # sent in the GET body is reflected, then served from cache to the body-less
        # victim request -> a persisted, cache-backed poisoning.
        vec = {"url": "https://shop/search", "vector_type": "fat_get",
               "vector_name": "q", "payload_kind": "value", "impact_hint": "reflected"}
        rec = confirm.confirm_vector(vec, {"param": "rdmncb"}, FatGetCacheSession("q"), {})
        self.assertTrue(rec["reflected_in_baseline"])   # canary echoed by the origin
        self.assertTrue(rec["persisted_on_clean"])      # still there on the clean read
        self.assertTrue(rec["cache_hit_on_clean"])      # and that read was a cache HIT

    def test_classify_impact_redirect_needs_the_canary_host(self):
        vec = {"impact_hint": "open_redirect"}
        to_canary = {"persisted_on_clean": True, "persisted_reflected": True,
                     "redirect_to_canary": True, "evidence": {}}
        self.assertEqual(confirm.classify_impact(vec, to_canary), "open_redirect")
        # A page that redirects anyway (trailing slash, http->https) has a Location on
        # the poisoned response too; that alone is not an attacker-chosen destination.
        own_redirect = {"persisted_on_clean": True, "persisted_reflected": True,
                        "evidence": {"redirect_poisoned": "https://shop/home/"}}
        self.assertEqual(confirm.classify_impact(vec, own_redirect), "reflected")

    def test_redirects_to_canary_reads_the_host_only(self):
        self.assertTrue(confirm._redirects_to_canary("https://rdmnab.redamon-poc.invalid/x", "rdmnab"))
        self.assertTrue(confirm._redirects_to_canary("//rdmnab.redamon-poc.invalid/x", "rdmnab"))
        # Token in the query of a same-site redirect: reflected, but the victim stays on site.
        self.assertFalse(confirm._redirects_to_canary("/login?next=rdmnab", "rdmnab"))
        self.assertFalse(confirm._redirects_to_canary("", "rdmnab"))

    def test_xss_context_helper(self):
        self.assertTrue(confirm._xss_context('<script src="//rdmnX.invalid/a.js"></script>', "rdmnX"))
        self.assertTrue(confirm._xss_context('<script>var u="rdmnX"</script>', "rdmnX"))
        self.assertTrue(confirm._xss_context('<body onload="track(\'rdmnX\')">', "rdmnX"))
        self.assertTrue(confirm._xss_context('<img src=x onerror="rdmnX">', "rdmnX"))
        self.assertFalse(confirm._xss_context("<p>benign rdmnX text</p>", "rdmnX"))
        self.assertFalse(confirm._xss_context("<a href='//rdmnX.invalid'>", "rdmnX"))  # link, not executable

    def test_xss_context_ignores_benign_placements(self):
        # Each of these matched the old patterns and was reported as critical stored XSS.
        benign = [
            '<img src="/logo.png" alt="results for rdmnX">',            # alt text, not src
            '<a onclick="track()" href="/?utm_source=rdmnX">x</a>',     # canary in href, not the handler
            '<script type="application/ld+json">{"url":"https://s/?u=rdmnX"}</script>',  # JSON-LD
            '<script id="__NEXT_DATA__" type="application/json">{"q":"rdmnX"}</script>',
            '<link rel=stylesheet href="https://rdmnX.redamon-poc.invalid/s.css">',
        ]
        for body in benign:
            self.assertFalse(confirm._xss_context(body, "rdmnX"), body)

    def test_script_type_allow_list_and_tag_anchoring(self):
        n = "rdmnX"
        self.assertTrue(confirm._xss_context(f'<script type="module">import("{n}")</script>', n))
        self.assertTrue(confirm._xss_context(f"<script type='text/javascript'>x='{n}'</script>", n))
        for body in (
            f'<script type="text/x-handlebars-template"><p>{n}</p></script>',  # inert template
            f'<script data-src="https://{n}.redamon-poc.invalid/a.js"></script>',  # lazy-load attr
            f'<p>set onload="{n}" in the docs</p>',                              # text, not a tag
            f"<p>see javascript:alert('{n}')</p>",                               # text, not a tag
        ):
            self.assertFalse(confirm._xss_context(body, n), body)
        self.assertFalse(confirm._script_src_canary(
            f'<script data-src="https://{n.lower()}.redamon-poc.invalid/a.js"></script>', n.lower()))

    def test_script_src_canary_requires_the_host(self):
        self.assertTrue(confirm._script_src_canary(
            '<script src="https://rdmnx.redamon-poc.invalid/app.js"></script>', "rdmnx"))
        self.assertTrue(confirm._script_src_canary("<script src=//rdmnx.redamon-poc.invalid/a.js>", "rdmnx"))
        # Canary in a same-site script's query string: an executable context, not a proof.
        body = '<script src="/js/app.js?ref=rdmnx"></script>'
        self.assertFalse(confirm._script_src_canary(body, "rdmnx"))
        self.assertTrue(confirm._xss_context(body, "rdmnx"))

    def test_classify_stored_xss_beats_hint(self):
        # A persisted canary as the HOST of a <script src> is stored XSS (critical), even
        # when the vector hint says open_redirect.
        vec = {"impact_hint": "open_redirect"}
        rec = {"persisted_on_clean": True, "persisted_reflected": True,
               "xss_context": True, "script_src_canary": True, "evidence": {}}
        self.assertEqual(confirm.classify_impact(vec, rec), "stored_xss")
        self.assertEqual(scoring.severity_for_impact("stored_xss"), ("critical", 9.3))

    def test_unproven_script_context_is_not_stored_xss(self):
        # An alphanumeric canary inside an inline script string proves where input
        # lands, not that a quote or </script> survives: high, not critical.
        vec = {"impact_hint": "reflected"}
        rec = {"persisted_on_clean": True, "persisted_reflected": True,
               "xss_context": True, "evidence": {}}
        self.assertEqual(confirm.classify_impact(vec, rec), "reflected_script")
        self.assertEqual(scoring.severity_for_impact("reflected_script")[0], "high")

    def test_body_change_is_not_labelled_reflected(self):
        # Node 217734's label: a differential body change echoed nothing.
        vec = {"impact_hint": "reflected"}
        rec = {"persisted_on_clean": True, "persisted_differential": True,
               "differential_change": "body", "evidence": {}}
        self.assertEqual(confirm.classify_impact(vec, rec), "response_change")

    def test_script_src_reflection_detected_as_xss(self):
        # The vulnerable fake reflects the host into <script src=//canary> -> stored XSS.
        rec = confirm.confirm_vector(self._vector(), {"param": "cb"}, VulnerableCacheSession("X-Forwarded-Host"), {})
        self.assertTrue(rec["xss_context"])
        self.assertEqual(confirm.classify_impact(self._vector(), rec), "stored_xss")


class TestWcvsVectorMapping(unittest.TestCase):
    def test_header_host_vector(self):
        v = scanner._wcvs_vector("https://x/", {"technique": "Header Poisoning", "vector_name": "X-Forwarded-Host"})
        self.assertEqual(v["vector_type"], "header")
        self.assertEqual(v["payload_kind"], "host")
        self.assertEqual(v["impact_hint"], "open_redirect")

    def test_param_vector_not_forced_to_header(self):
        v = scanner._wcvs_vector("https://x/", {"technique": "Parameter Cloaking", "vector_name": "utm_source"})
        self.assertEqual(v["vector_type"], "param")
        self.assertEqual(v["technique"], "unkeyed_param")

    def test_deception_vector(self):
        v = scanner._wcvs_vector("https://x/", {"technique": "Deception", "vector_name": "css"})
        self.assertEqual(v["vector_type"], "path")
        self.assertEqual(v["impact_hint"], "deception")

    def test_non_host_header_vector_is_value_reflected(self):
        v = scanner._wcvs_vector("https://x/", {"technique": "Header Poisoning", "vector_name": "X-Forwarded-Scheme"})
        self.assertEqual(v["vector_type"], "header")
        self.assertEqual(v["payload_kind"], "value")
        self.assertEqual(v["impact_hint"], "reflected")

    def test_technique_normalisation(self):
        self.assertEqual(scanner._wcvs_technique("Web Cache Deception"), "cache_deception")
        self.assertEqual(scanner._wcvs_technique("Parameter Pollution"), "unkeyed_param")
        self.assertEqual(scanner._wcvs_technique("FatGET body"), "fat_get")
        self.assertEqual(scanner._wcvs_technique("HTTP Request Smuggling"), "request_smuggling")
        self.assertEqual(scanner._wcvs_technique("anything else"), "unkeyed_header")
        self.assertEqual(scanner._wcvs_technique(""), "unkeyed_header")

    def test_wcvs_vector_carries_reason(self):
        v = scanner._wcvs_vector("https://x/", {"technique": "Header Poisoning",
                                                "vector_name": "X-Host", "reason": "reflected"})
        self.assertEqual(v["source"], "wcvs")
        self.assertEqual(v["wcvs_reason"], "reflected")

    def test_fat_get_vector_not_forced_to_header(self):
        # A WCVS fat-GET hit must re-test as a fat_get body vector, not a header
        # (the old default), so the native confirmation matches WCVS's transport.
        v = scanner._wcvs_vector("https://x/", {"technique": "FatGET body reflection",
                                                "vector_name": "q"})
        self.assertEqual(v["vector_type"], "fat_get")
        self.assertEqual(v["technique"], "fat_get")
        self.assertEqual(v["payload_kind"], "value")

    def test_normalization_vector_maps_to_path_param(self):
        v = scanner._wcvs_vector("https://x/", {"technique": "Path normalization",
                                                "vector_name": "utm_source"})
        self.assertEqual(v["vector_type"], "path_param")
        self.assertEqual(v["technique"], "normalization")


class TestScannerTargets(unittest.TestCase):
    def _recon(self, urls, roe_excluded=None):
        return {
            "domain": "shop.test",
            "http_probe": {"by_url": {u: {"url": u, "status_code": 200} for u in urls}},
            "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
            "metadata": {"roe": {"ROE_ENABLED": bool(roe_excluded),
                                 "ROE_EXCLUDED_HOSTS": roe_excluded or []}},
        }

    def test_collect_targets_from_http_probe(self):
        rd = self._recon(["https://shop.test/home", "https://api.shop.test/v1"])
        urls = scanner._collect_target_urls(rd, {})
        self.assertIn("https://shop.test/home", urls)
        self.assertIn("https://api.shop.test/v1", urls)

    def test_roe_filters_excluded_host(self):
        rd = self._recon(["https://shop.test/home", "https://secret.test/x"], roe_excluded=["secret.test"])
        urls = scanner._collect_target_urls(rd, {})
        self.assertIn("https://shop.test/home", urls)
        self.assertNotIn("https://secret.test/x", urls)

    def test_roe_excludes_subdomains_of_excluded_host(self):
        rd = self._recon(["https://shop.test/home", "https://api.secret.test/x"], roe_excluded=["secret.test"])
        urls = scanner._collect_target_urls(rd, {})
        self.assertIn("https://shop.test/home", urls)
        self.assertNotIn("https://api.secret.test/x", urls)  # subdomain suffix match

    def test_roe_from_settings_takes_effect(self):
        rd = self._recon(["https://shop.test/home", "https://blocked.test/x"])
        urls = scanner._collect_target_urls(
            rd, {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["blocked.test"]})
        self.assertNotIn("https://blocked.test/x", urls)

    def test_host_excluded_helper_exact_and_suffix(self):
        ex = {"evil.test"}
        self.assertTrue(scanner._host_excluded("evil.test", ex))
        self.assertTrue(scanner._host_excluded("a.b.evil.test", ex))
        self.assertFalse(scanner._host_excluded("notevil.test", ex))  # not a real suffix boundary
        self.assertFalse(scanner._host_excluded("evil.test.com", ex))

    def test_max_urls_cap_enforced(self):
        many = [f"https://h{i}.shop.test/" for i in range(260)]
        urls = scanner._collect_target_urls(self._recon(many), {})
        self.assertLessEqual(len(urls), scanner._MAX_URLS)

    def test_retry_session_config(self):
        s = scanner._build_retry_session()
        try:
            self.assertEqual(s.headers["User-Agent"], "RedAmon-CachePoison/1.0")
            adapter = s.get_adapter("https://x/")
            self.assertIn(429, adapter.max_retries.status_forcelist)
        finally:
            s.close()

    def test_endpoints_from_resource_enum_become_targets(self):
        # Regression: partial recon must scan graph Endpoints, not only BaseURLs.
        # build_target_urls reads resource_enum.by_base_url[base]["endpoints"][path].
        rd = {
            "domain": "shop.test",
            "http_probe": {"by_url": {"https://shop.test/": {"url": "https://shop.test/", "status_code": 200}}},
            "resource_enum": {"by_base_url": {
                "https://shop.test": {"endpoints": {
                    "/api/users": {"method": "GET", "parameters": {"query": []}},
                    "/admin/settings": {"method": "GET", "parameters": {"query": []}},
                }}
            }},
            "metadata": {},
        }
        urls = scanner._collect_target_urls(rd, {})
        self.assertIn("https://shop.test/api/users", urls)
        self.assertIn("https://shop.test/admin/settings", urls)

    def test_disabled_returns_empty_structure(self):
        rd = self._recon(["https://shop.test/home"])
        out = scanner.run_cache_scan(rd, {"WEB_CACHE_POISON_ENABLED": False})
        self.assertNotIn("cache_scan", out)

    def test_no_targets_writes_empty_result(self):
        rd = {"http_probe": {"by_url": {}}, "metadata": {}}
        out = scanner.run_cache_scan(rd, {"WEB_CACHE_POISON_ENABLED": True})
        self.assertIn("cache_scan", out)
        self.assertEqual(out["cache_scan"]["summary"]["total_findings"], 0)


class TestScannerRun(unittest.TestCase):
    """Full run_cache_scan behaviours with the network + WCVS stubbed out."""

    def _recon(self, url="https://shop.test/home"):
        return {"http_probe": {"by_url": {url: {"url": url, "status_code": 200}}},
                "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
                "metadata": {}}

    def _run(self, session_factory, settings=None, wcvs=None):
        orig_s, orig_w = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
        scanner._build_retry_session = lambda *a, **k: session_factory()
        scanner.wcvs_runner.run_wcvs = lambda urls, s, **k: (wcvs or [])
        try:
            base = {"WEB_CACHE_POISON_ENABLED": True}
            base.update(settings or {})
            return scanner.run_cache_scan(self._recon(), base)["cache_scan"]
        finally:
            scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_s, orig_w

    def test_not_cacheable_url_is_scanned_but_yields_nothing(self):
        cs = self._run(NoCacheSession)
        self.assertEqual(cs["summary"]["total_findings"], 0)
        self.assertEqual(cs["summary"]["cacheable_urls"], 0)
        # The URL is still accounted for in by_target with a not-cacheable oracle.
        entry = cs["by_target"]["https://shop.test/home"]
        self.assertFalse(entry["oracle"]["cacheable"])

    def test_run_metadata_fields_present(self):
        cs = self._run(lambda: VulnerableCacheSession("X-Forwarded-Host"))
        md = cs["scan_metadata"]
        self.assertEqual(md["engine"], "wcvs+native-confirm")
        self.assertEqual(md["scan_profile"], "safe-confirm")
        self.assertEqual(md["total_urls_scanned"], 1)
        self.assertEqual(md["wcvs_candidates"], 0)
        self.assertIn("duration_seconds", md)

    def test_wcvs_candidate_is_counted_and_confirmed(self):
        wcvs = [{"url": "https://shop.test/home", "vector_name": "X-Forwarded-Host",
                 "technique": "Header Poisoning"}]
        cs = self._run(lambda: VulnerableCacheSession("X-Forwarded-Host"), wcvs=wcvs)
        self.assertEqual(cs["scan_metadata"]["wcvs_candidates"], 1)
        # The WCVS-sourced vector confirmed (engine attribution preserved).
        engines = {f["source_engine"] for f in cs["findings"]}
        self.assertIn("wcvs", engines)

    def test_isolated_wrapper_deep_copies_and_returns_payload(self):
        orig_s, orig_w = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
        scanner._build_retry_session = lambda *a, **k: NoCacheSession()
        scanner.wcvs_runner.run_wcvs = lambda urls, s, **k: []
        try:
            combined = self._recon()
            payload = scanner.run_cache_scan_isolated(combined, {"WEB_CACHE_POISON_ENABLED": True})
            self.assertIn("summary", payload)
            # The original combined_result must NOT be mutated (deep-copy isolation).
            self.assertNotIn("cache_scan", combined)
        finally:
            scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_s, orig_w


class TestParallelConfirmation(unittest.TestCase):
    """The parallel per-URL fan-out must be thread-safe and equivalent to
    the sequential path (no lost / duplicated / corrupted findings)."""

    def _recon(self, n):
        urls = {f"https://shop.test/p{i}": {"url": f"https://shop.test/p{i}", "status_code": 200}
                for i in range(n)}
        return {"http_probe": {"by_url": urls},
                "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
                "metadata": {}}

    def _run(self, n, workers):
        # Each worker/URL gets its own fresh stateful vulnerable-cache fake (mirrors
        # the real per-thread Session). WCVS is stubbed out (native path only).
        orig_session, orig_wcvs = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
        scanner._build_retry_session = lambda *a, **k: VulnerableCacheSession("X-Forwarded-Host")
        scanner.wcvs_runner.run_wcvs = lambda urls, settings, **k: []
        try:
            out = scanner.run_cache_scan(self._recon(n), {
                "WEB_CACHE_POISON_ENABLED": True,
                "WEB_CACHE_POISON_CONFIRM_WORKERS": workers,
            })
            return out["cache_scan"]
        finally:
            scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_session, orig_wcvs

    def test_parallel_equivalent_to_sequential(self):
        seq = self._run(8, workers=1)
        par = self._run(8, workers=4)
        # The vulnerable fake reflects X-Forwarded-Host -> one Confirmed finding per URL.
        self.assertEqual(seq["summary"]["total_findings"], 8)
        self.assertEqual(par["summary"]["total_findings"], 8)
        self.assertEqual(seq["summary"]["confirmed"], par["summary"]["confirmed"])
        self.assertEqual(len(par["by_target"]), 8)  # every URL accounted for, no races

    def test_workers_clamped_and_safe(self):
        # Out-of-range worker counts must not crash (clamped to 1..16).
        for w in (0, -3, 999):
            cs = self._run(3, workers=w)
            self.assertEqual(cs["summary"]["total_findings"], 3)


class TestDifferentialIntegration(unittest.TestCase):
    """End-to-end run_cache_scan over the native path with non-reflective fakes."""

    def _recon(self, url="https://shop.test/login"):
        return {"http_probe": {"by_url": {url: {"url": url, "status_code": 200}}},
                "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
                "metadata": {}}

    def _run(self, session_factory):
        orig_session, orig_wcvs = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
        scanner._build_retry_session = lambda *a, **k: session_factory()
        scanner.wcvs_runner.run_wcvs = lambda urls, settings, **k: []
        try:
            out = scanner.run_cache_scan(self._recon(), {"WEB_CACHE_POISON_ENABLED": True})
            return out["cache_scan"]
        finally:
            scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_session, orig_wcvs

    def test_non_reflective_finding_surfaces_end_to_end(self):
        cs = self._run(lambda: DifferentialCacheSession("X-Forwarded-Proto"))
        self.assertEqual(cs["summary"]["total_findings"], 1)
        self.assertEqual(cs["summary"]["strong"], 1)
        self.assertEqual(cs["summary"]["confirmed"], 0)
        f = cs["findings"][0]
        self.assertEqual(f["detection_mode"], "differential")
        self.assertEqual(f["impact"], "response_change")  # fixed payload: not attacker-routed
        self.assertEqual(f["evidence"]["differential_change"], "location")
        self.assertEqual(f["cache_header"], "X-Forwarded-Proto")

    def test_dynamic_page_yields_no_findings(self):
        cs = self._run(DynamicNoiseSession)
        self.assertEqual(cs["summary"]["total_findings"], 0)
        # The URL was still scanned and judged cacheable (oracle saw x-cache).
        self.assertEqual(cs["summary"]["cacheable_urls"], 1)


class TestFalsePositiveRegressions(unittest.TestCase):
    """Every fake here is NOT vulnerable, and each was scored at or above the default
    0.8 floor (so written to the graph) before the post-poison control, the
    param-borne body rule and the explicit-MISS rule existed."""

    _SCHEME = {"url": "https://shop/archive", "vector_type": "header",
               "vector_name": "X-Forwarded-Proto", "payload_kind": "scheme",
               "impact_hint": "open_redirect", "technique": "unkeyed_header"}
    # Node 217734: fat GET, utm_source in the request body, a body-only differential.
    _FAT_GET = {"url": "https://shop/2021/01/", "vector_type": "fat_get",
                "vector_name": "utm_source", "payload_kind": "value",
                "impact_hint": "reflected", "technique": "fat_get"}
    _PARAM = {"url": "https://shop/landing", "vector_type": "param",
              "vector_name": "utm_source", "payload_kind": "value",
              "impact_hint": "reflected", "technique": "unkeyed_param"}

    def _assert_below_floor(self, rec):
        conf, _ = scoring.score_finding(rec)
        self.assertLess(conf, 0.8, rec)

    def test_page_drift_between_baseline_and_poison_is_not_poisoning(self):
        rec = confirm.confirm_vector(self._SCHEME, {"param": "rdmncb"}, TimeDriftSession(), {})
        self.assertEqual(rec["differential_change"], "body")  # the drift looks like a change...
        self.assertEqual(rec["control_check"], "baseline_drift")  # ...a fresh clean slot shows too
        self.assertFalse(rec["persisted_on_clean"])
        self._assert_below_floor(rec)

    def test_node_217734_fat_get_body_drift_is_not_poisoning(self):
        rec = confirm.confirm_vector(self._FAT_GET, {"param": "rdmncb"}, TimeDriftSession(), {})
        self.assertEqual(rec["differential_change"], "")  # unechoed body change: not for a param
        self.assertFalse(rec["persisted_on_clean"])
        self._assert_below_floor(rec)

    def test_param_body_change_without_echo_is_ignored_even_when_cached(self):
        # The same body swap that counts for a header proves nothing for a parameter.
        class _ParamBodySwap(_CachedOrigin):
            def render(self, url, headers, data):
                return 200, "<maintenance/>" if "utm_source=" in url else "<live/>"
        rec = confirm.confirm_vector(self._PARAM, {"param": "rdmncb"}, _ParamBodySwap(), {})
        self.assertEqual(rec["differential_change"], "")
        self._assert_below_floor(rec)

    def test_one_off_origin_error_is_not_cpdos(self):
        rec = confirm.confirm_vector(self._SCHEME, {"param": "rdmncb"}, FlakyPoisonSession(), {})
        self.assertEqual(rec["differential_change"], "status")
        self.assertEqual(rec["control_check"], "not_reproduced")
        self._assert_below_floor(rec)

    def test_waf_block_mid_sequence_is_not_cpdos(self):
        rec = confirm.confirm_vector(self._SCHEME, {"param": "rdmncb"}, WafBlockSession(), {})
        self.assertEqual(rec["differential_change"], "status")
        self.assertEqual(rec["control_check"], "baseline_drift")
        self._assert_below_floor(rec)

    def test_origin_state_replaying_the_canary_is_not_poisoning(self):
        rec = confirm.confirm_vector(self._PARAM, {"param": "rdmncb"}, OriginStateSession(), {})
        self.assertTrue(rec["reflected_in_baseline"])
        self.assertEqual(rec["control_check"], "canary_on_fresh_slot")
        self.assertFalse(rec["persisted_reflected"])
        self._assert_below_floor(rec)

    def test_explicit_miss_on_the_clean_read_is_rejected(self):
        conf, tier = scoring.score_finding({
            "reflected_in_baseline": True, "persisted_on_clean": True,
            "persisted_reflected": True, "clean_cache_state": "miss",
            "repeated_ok": True, "stable": True})
        self.assertEqual(tier, "Rejected")

    def test_behavioural_change_needs_an_explicit_hit(self):
        base = {"persisted_on_clean": True, "persisted_reflected": False,
                "persisted_differential": True, "repeated_ok": True, "stable": True}
        self.assertLess(scoring.score_finding({**base, "clean_cache_state": "unknown"})[0], 0.8)
        self.assertEqual(scoring.score_finding({**base, "clean_cache_state": "hit"})[1], "Strong")

    def test_reflected_canary_behind_a_silent_cache_stays_strong(self):
        conf, tier = scoring.score_finding({
            "reflected_in_baseline": True, "persisted_on_clean": True,
            "persisted_reflected": True, "clean_cache_state": "unknown",
            "repeated_ok": True, "stable": True})
        self.assertEqual(tier, "Strong")
        self.assertGreaterEqual(conf, 0.8)

    def test_age_only_cache_keeps_a_real_reflected_poisoning(self):
        # A cache that marks hits only with Age (0 within the same second): the clean
        # read is not an explicit MISS, so our canary on it still makes Strong.
        class _AgeOnlyCache(_CachedOrigin):
            def get(self, url, headers=None, data=None, **kwargs):
                if url in self.store:
                    return FakeResponse(self.store[url][1], {"age": "0"})
                xfh = (headers or {}).get("X-Forwarded-Host", "cdn.shop")
                self.store[url] = (200, f"<link href=//{xfh}/s.css>")
                return FakeResponse(self.store[url][1], {})

        header = {"url": "https://shop/home", "vector_type": "header",
                  "vector_name": "X-Forwarded-Host", "payload_kind": "host",
                  "impact_hint": "open_redirect"}
        rec = confirm.confirm_vector(header, {"param": "cb"}, _AgeOnlyCache(), {})
        self.assertEqual(rec["clean_cache_state"], "unknown")
        self.assertEqual(scoring.score_finding(rec)[1], "Strong")

    def test_a_drift_seen_by_one_vector_untrusts_the_dimension_for_the_url(self):
        sess = TimeDriftSession(flip_after=confirm._PROFILE_SAMPLES)  # the profile renders agree
        profile = confirm.clean_profile(self._SCHEME["url"], "rdmncb", sess)
        self.assertIn("body", profile["trusted"])
        confirm.confirm_vector(self._SCHEME, {"param": "rdmncb"}, sess, {}, baseline=profile)
        self.assertNotIn("body", profile["trusted"])  # later vectors of the URL skip it
        self.assertFalse(profile["stable"])

    def test_a_failed_reproduction_untrusts_the_dimension_for_the_url(self):
        # The one-off 503 lands on the poison (render 9, after the 8 profile renders);
        # the reproduction gets the page's normal 200, so status flaps on this URL.
        sess = FlakyPoisonSession(fail_on_render=confirm._PROFILE_SAMPLES + 1)
        profile = confirm.clean_profile(self._SCHEME["url"], "rdmncb", sess)
        self.assertIn("status", profile["trusted"])
        rec = confirm.confirm_vector(self._SCHEME, {"param": "rdmncb"}, sess, {}, baseline=profile)
        self.assertEqual(rec["control_check"], "not_reproduced")
        self.assertNotIn("status", profile["trusted"])

    def test_rate_limited_control_rejects_without_untrusting_the_url(self):
        class _RateLimitedControl(_CachedOrigin):
            def render(self, url, headers, data):
                if headers.get("X-Forwarded-Proto"):
                    return 200, "<maintenance/>"
                if self.renders == confirm._PROFILE_SAMPLES + 2:  # profile, poison, control
                    return 429, "slow down"
                return 200, "<live/>"

        sess = _RateLimitedControl()
        profile = confirm.clean_profile(self._SCHEME["url"], "rdmncb", sess)
        rec = confirm.confirm_vector(self._SCHEME, {"param": "rdmncb"}, sess, {}, baseline=profile)
        self.assertEqual(rec["control_check"], "rate_limited")
        self._assert_below_floor(rec)
        self.assertIn("body", profile["trusted"])  # a rate limit is not the page moving

    def test_reflected_canary_seen_once_is_not_strong_behind_a_silent_cache(self):
        conf, tier = scoring.score_finding({
            "reflected_in_baseline": True, "persisted_on_clean": True,
            "persisted_reflected": True, "clean_cache_state": "unknown",
            "repeated_ok": False, "stable": True})
        self.assertLess(conf, 0.8)

    def test_malformed_bracketed_host_does_not_raise(self):
        self.assertFalse(confirm._script_src_canary('<script src="https://[cdn]/a.js"></script>', "rdmnx"))
        self.assertFalse(confirm._redirects_to_canary("https://[bad/x", "rdmnx"))

    def test_wcvs_framework_param_keeps_its_body_detection(self):
        # __nextDataReq switches Next.js to its JSON data response: a body change with
        # no echo. Surfaced by WCVS first, it used to arrive as a generic param.
        class _NextDataCache(_CachedOrigin):
            def get(self, url, headers=None, data=None, **kwargs):
                import re as _re
                key = _re.sub(r"[?&]__nextDataReq=[^&]*", "", url)  # the cache ignores it
                if key in self.store:
                    return FakeResponse(self.store[key][1], {"x-cache": "hit", "age": "2"})
                body = '{"pageProps":{}}' if "__nextDataReq=" in url else "<html>page</html>"
                self.store[key] = (200, body)
                return FakeResponse(body, {"x-cache": "miss"})

        vec = scanner._wcvs_vector("https://shop/home", {"technique": "Parameter Cloaking",
                                                         "vector_name": "__nextDataReq"})
        self.assertEqual(vec["technique"], "framework_next")
        rec = confirm.confirm_vector(vec, {"param": "rdmncb"}, _NextDataCache(), {})
        self.assertEqual(scoring.score_finding(rec)[1], "Strong")

    def test_real_poisonings_pass_the_control(self):
        header = {"url": "https://shop/home", "vector_type": "header",
                  "vector_name": "X-Forwarded-Host", "payload_kind": "host",
                  "impact_hint": "open_redirect"}
        rec = confirm.confirm_vector(header, {"param": "cb"}, VulnerableCacheSession(), {})
        self.assertEqual(rec["control_check"], "passed")
        self.assertEqual(scoring.score_finding(rec)[1], "Confirmed")
        rec = confirm.confirm_vector(self._SCHEME, {"param": "cb"}, BodyPoisonCacheSession(), {})
        self.assertEqual(rec["control_check"], "passed")
        self.assertEqual(scoring.score_finding(rec)[1], "Strong")

    def test_fat_get_curl_carries_the_body(self):
        # The stored reproduction was a plain GET, so validators re-tested the param in
        # the query string instead of the body.
        vec = {"url": "https://shop/search", "vector_type": "fat_get", "vector_name": "q",
               "payload_kind": "value", "impact_hint": "reflected"}
        rec = confirm.confirm_vector(vec, {"param": "rdmncb"}, FatGetCacheSession("q"), {})
        curl = rec["evidence"]["curl_verify"]
        self.assertIn("-X GET", curl)
        self.assertIn(f"--data 'q={rec['evidence']['canary']}'", curl)


class TestScannerIsolationAndProfile(unittest.TestCase):
    _URL = "https://shop.test/2021/01/"

    def _run(self, session):
        orig_s, orig_w = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
        scanner._build_retry_session = lambda *a, **k: session
        scanner.wcvs_runner.run_wcvs = lambda urls, s, **k: []
        try:
            rd = {"http_probe": {"by_url": {self._URL: {"url": self._URL, "status_code": 200}}},
                  "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
                  "metadata": {}}
            return scanner.run_cache_scan(rd, {"WEB_CACHE_POISON_ENABLED": True})["cache_scan"]
        finally:
            scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_s, orig_w

    def test_query_ignoring_cache_is_skipped_before_any_poison(self):
        sess = QueryIgnoringCacheSession()
        cs = self._run(sess)
        self.assertEqual(cs["summary"]["total_findings"], 0)
        self.assertIn("cannot be isolated", cs["by_target"][self._URL]["skipped"])
        self.assertEqual(sess.poison_requests, 0)  # nothing reached the real entry

    def test_two_variant_page_yields_no_findings(self):
        # Per-vector baseline pairs agree half the time on this page; the shared
        # per-URL profile sees both variants and stops trusting the body.
        cs = self._run(PairedVariantSession())
        self.assertEqual(cs["summary"]["total_findings"], 0)
        self.assertEqual(cs["summary"]["cacheable_urls"], 1)

    def test_shared_profile_is_what_stops_a_scripted_variant_page(self):
        # A vector's own two-slot baseline is fooled: this alone writes a false finding...
        alone = confirm.confirm_vector(TestFalsePositiveRegressions._SCHEME, {"param": "rdmncb"},
                                       ScriptedVariantSession(), {})
        self.assertEqual(scoring.score_finding(alone)[1], "Strong")
        # ...while the scan hands every vector the URL's one shared profile.
        seen = []
        orig = confirm.confirm_vector

        def spy(*args, baseline=None, **kwargs):
            seen.append(baseline)
            return orig(*args, baseline=baseline, **kwargs)

        confirm.confirm_vector = spy
        try:
            cs = self._run(ScriptedVariantSession())
        finally:
            confirm.confirm_vector = orig
        self.assertEqual(cs["summary"]["total_findings"], 0)
        self.assertTrue(seen and seen[0] is not None)
        self.assertTrue(all(b is seen[0] for b in seen))

    def test_clean_profile_marks_a_flapping_body_untrusted(self):
        prof = confirm.clean_profile(self._URL, "rdmncb", PairedVariantSession())
        self.assertNotIn("body", prof["trusted"])
        self.assertFalse(prof["stable"])
        prof = confirm.clean_profile(self._URL, "rdmncb", BodyPoisonCacheSession())
        self.assertEqual(prof["trusted"], {"status", "location", "body"})


class TestStatelessSession(unittest.TestCase):
    @staticmethod
    def _offer_cookie(session):
        import http.client
        import io

        class _Raw:
            pass

        raw, orig = _Raw(), _Raw()
        orig.msg = http.client.parse_headers(io.BytesIO(b"Set-Cookie: utm_source=rdmnab; Path=/\r\n\r\n"))
        raw._original_response = orig
        req = requests.Request("GET", "https://shop.test/").prepare()
        requests.cookies.extract_cookies_to_jar(session.cookies, req, raw)

    def test_scanner_session_never_stores_a_cookie(self):
        plain = requests.Session()
        s = scanner._build_retry_session()
        try:
            self._offer_cookie(plain)
            self.assertEqual(len(plain.cookies), 1)  # the harness really sets one...
            self._offer_cookie(s)
            self.assertEqual(len(s.cookies), 0)      # ...and the scanner's session refuses it
        finally:
            plain.close()
            s.close()


class TestGraphContract(unittest.TestCase):
    """build_finding must never emit a key the graph mixin doesn't know about
    (the data-loss tripwire). Guards against drift between the two files."""

    def _finding(self, mode="differential", diff="location"):
        vector = {"url": "https://shop/login", "vector_type": "header",
                  "vector_name": "X-Forwarded-Proto", "source": "hypothesis",
                  "technique": "unkeyed_header"}
        confirmation = {"detection_mode": mode,
                        "evidence": {"baseline_hash": "a", "poisoned_hash": "b",
                                     "clean_validation_hash": "c", "poc_link": "p",
                                     "curl_verify": "curl", "canary": "x",
                                     "differential_change": diff}}
        return normalizers.build_finding(vector, confirmation, 0.9, "Strong",
                                         "open_redirect", "high", 7.4, ["x-cache: hit"])

    def test_finding_keys_within_graph_contract(self):
        try:
            from graph_db.mixins.cache_mixin import KNOWN_FINDING_KEYS, KNOWN_EVIDENCE_KEYS
        except Exception as e:  # pragma: no cover - graph_db deps absent
            self.skipTest(f"graph_db import unavailable: {e}")
        f = self._finding()
        self.assertEqual(set(f.keys()) - KNOWN_FINDING_KEYS, set())
        self.assertEqual(set(f["evidence"].keys()) - KNOWN_EVIDENCE_KEYS, set())

    def test_real_confirmation_keys_within_graph_contract(self):
        # Built from a live confirm_vector record, so evidence the confirmation adds is
        # checked too, not only the hand-written dict above.
        try:
            from graph_db.mixins.cache_mixin import KNOWN_EVIDENCE_KEYS
        except Exception as e:  # pragma: no cover - graph_db deps absent
            self.skipTest(f"graph_db import unavailable: {e}")
        vec = {"url": "https://shop/home", "vector_type": "header", "vector_name": "X-Forwarded-Host",
               "payload_kind": "host", "impact_hint": "open_redirect", "source": "hypothesis",
               "technique": "unkeyed_header"}
        rec = confirm.confirm_vector(vec, {"param": "rdmncb"}, VulnerableCacheSession(), {})
        f = normalizers.build_finding(vec, rec, 0.97, "Confirmed", "stored_xss", "critical", 9.3, [])
        self.assertEqual(set(f["evidence"]) - KNOWN_EVIDENCE_KEYS, set())
        self.assertEqual(f["evidence"]["clean_cache_state"], "hit")
        self.assertEqual(f["evidence"]["control_check"], "passed")
        self.assertEqual(f["evidence"]["xss_context"], "proven")

    def test_description_does_not_overstate_the_tier(self):
        try:
            from graph_db.mixins.cache_mixin import CacheMixin
        except Exception as e:  # pragma: no cover - graph_db deps absent
            self.skipTest(f"graph_db import unavailable: {e}")

        class _Session:
            def __init__(self):
                self.calls = []

            def run(self, query, **params):
                self.calls.append(params)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        class _Driver:
            def __init__(self):
                self.s = _Session()

            def session(self):
                return self.s

        writer = CacheMixin()
        writer.driver = _Driver()
        descriptions = {}
        for tier in ("Confirmed", "Strong"):
            writer.driver.s.calls.clear()
            writer.update_graph_from_cache_scan(
                {"cache_scan": {"findings": [self._finding_with_tier(tier)]}}, "u", "p")
            descriptions[tier] = writer.driver.s.calls[0]["props"]["description"]
        self.assertIn("confirmed", descriptions["Confirmed"])
        self.assertNotIn("confirmed", descriptions["Strong"])
        self.assertIn("likely", descriptions["Strong"])
        self.assertIn("detected by differential", descriptions["Strong"])

    def _finding_with_tier(self, tier):
        f = self._finding()
        f["confidence_tier"] = tier
        return f

    def test_detection_mode_present_for_reflected_default(self):
        # A legacy confirmation without detection_mode still yields a valid finding.
        f = normalizers.build_finding(
            {"url": "https://x/", "vector_type": "header", "vector_name": "X-Host"},
            {"evidence": {}}, 0.97, "Confirmed", "open_redirect", "high", 7.4, [])
        self.assertEqual(f["detection_mode"], "reflected")


class TestSmoke(unittest.TestCase):
    """Cheap import + minimal end-to-end sanity for the whole package."""

    def test_package_exports(self):
        from recon.cache_scan import run_cache_scan, run_cache_scan_isolated
        self.assertTrue(callable(run_cache_scan))
        self.assertTrue(callable(run_cache_scan_isolated))

    def test_isolated_wrapper_returns_only_payload(self):
        orig_session, orig_wcvs = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
        scanner._build_retry_session = lambda *a, **k: VulnerableCacheSession("X-Forwarded-Host")
        scanner.wcvs_runner.run_wcvs = lambda urls, settings, **k: []
        try:
            from recon.cache_scan import run_cache_scan_isolated
            combined = {"http_probe": {"by_url": {"https://shop.test/": {"url": "https://shop.test/", "status_code": 200}}},
                        "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
                        "metadata": {}}
            payload = run_cache_scan_isolated(combined, {"WEB_CACHE_POISON_ENABLED": True})
            # The wrapper returns ONLY this tool's payload, not the whole combined_result.
            self.assertIn("summary", payload)
            self.assertIn("findings", payload)
            self.assertNotIn("http_probe", payload)
        finally:
            scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_session, orig_wcvs


if __name__ == "__main__":
    unittest.main()

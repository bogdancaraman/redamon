"""Cache-poisoning follow-ups to the v6.25.1 false-positive fix.

A field report's cache rows (a third-party script loader alternating between
two body variants) are covered by v6.25.1's 8-sample profile, control slot
and reproductions. Three gaps remained and are pinned here:

- a vector that had to sample its own baseline took only two samples;
- the deception probe called a page "personalised" on one signed-in /
  anonymous pair, which a two-variant public page passes half the time;
- the per-URL record never said the page's own baseline was unstable
  (tested with the scanner harness in test_cache_scan.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.cache_scan import confirm, deception


class FakeResponse:
    def __init__(self, body="", headers=None, status=200):
        self.text = body
        self.headers = headers or {}
        self.status_code = status


class CountingSession:
    def __init__(self):
        self.calls = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        self.calls += 1
        return FakeResponse("<html>same</html>", {"x-cache": "miss"})


_SETTINGS = {
    "TARGET_DOMAIN": "shop.test",
    "AUTH_PROFILE": {"authType": "cookie", "authValue": "session=abc", "reconEnabled": True},
}
_URL = "https://shop.test/landing"
_ORACLE = {"signals": ["x-cache"]}


class TwoVariantPublicCacheSession:
    """NOT vulnerable. A public page that alternates between two variants per
    origin render, whatever the session, behind a cache that stores static-suffix
    URLs by extension. Its cached copy leaks nothing."""

    VARIANTS = ("<html>promo A</html>", "<html>promo B</html>")

    def __init__(self):
        self.renders = 0
        self.store = {}

    def _render(self):
        body = self.VARIANTS[self.renders % 2]
        self.renders += 1
        return body

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        path = url.split("?", 1)[0]
        if any(ext in path for ext in (".css", ".js", ".jpg")):
            if url in self.store:
                return FakeResponse(self.store[url], {"x-cache": "hit", "age": "3"})
            body = self._render()
            self.store[url] = body
            return FakeResponse(body, {"x-cache": "miss"})
        return FakeResponse(self._render(), {"x-cache": "miss"})


class PersonalisedLeakSession(TwoVariantPublicCacheSession):
    """Vulnerable. The authenticated view is stable and private; the origin
    ignores a static suffix and the cache serves the planted copy to anyone."""

    SENSITIVE = "<html>orders for user=alice</html>"

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        authed = any(k.lower() == "cookie" for k in (headers or {}))
        path = url.split("?", 1)[0]
        if any(ext in path for ext in (".css", ".js", ".jpg")):
            if url in self.store:
                return FakeResponse(self.store[url], {"x-cache": "hit", "age": "3"})
            body = self.SENSITIVE if authed else self._render()
            self.store[url] = body
            return FakeResponse(body, {"x-cache": "miss"})
        return FakeResponse(self.SENSITIVE if authed else self._render(), {"x-cache": "miss"})


def test_vector_without_a_shared_profile_samples_the_full_profile():
    sess = CountingSession()
    vector = {"url": "https://shop.test/a", "vector_type": "header", "vector_name": "X-Forwarded-Scheme",
              "payload_kind": "scheme", "impact_hint": "dos"}
    confirm.confirm_vector(vector, {"param": "rdmncb"}, sess, {})
    # profile samples + poison + clean read on the poison slot
    assert sess.calls >= confirm._PROFILE_SAMPLES + 2


def test_two_variant_public_page_is_not_deception():
    for offset in range(4):
        sess = TwoVariantPublicCacheSession()
        sess.renders = offset  # every phase of the alternation
        assert deception.deception_probe(_URL, _ORACLE, sess, _SETTINGS, timeout=2) is None, offset


def test_personalised_page_leaking_from_cache_is_still_deception():
    f = deception.deception_probe(_URL, _ORACLE, PersonalisedLeakSession(), _SETTINGS, timeout=2)
    assert f is not None
    assert f["impact"] == "deception"
    assert f["confidence_tier"] == "Confirmed"


def test_an_anonymous_view_matching_the_authenticated_one_is_not_personalised():
    class SameForEveryone(PersonalisedLeakSession):
        def _render(self):
            return self.SENSITIVE
    assert deception.deception_probe(_URL, _ORACLE, SameForEveryone(), _SETTINGS, timeout=2) is None


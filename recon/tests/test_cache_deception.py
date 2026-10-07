"""
Unit tests for the class-10 web-cache-deception probe
recon.cache_scan.deception.deception_probe().

The probe is auth-aware: it runs only with an in-scope auth profile, and confirms a
finding only when a static-suffix URL serves the AUTHENTICATED page from cache to an
UNAUTHENTICATED request.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.cache_scan import deception


class FakeResponse:
    def __init__(self, body="", headers=None, status=200):
        self.text = body
        self.headers = headers or {}
        self.status_code = status


class DeceptionCacheSession:
    """Static-suffix URL serves the sensitive page (origin ignores the suffix) and the
    cache stores it by extension, then serves it to an anonymous request as a HIT."""

    SENSITIVE = "SENSITIVE dashboard for user=alice"
    ANON = "generic public login page"

    def __init__(self, auth_header="cookie"):
        self.auth_header = auth_header.lower()
        self.store = {}

    def _authed(self, headers):
        return any(k.lower() == self.auth_header for k in (headers or {}))

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        authed = self._authed(headers)
        path = url.split("?", 1)[0]
        is_static = any(path.endswith(ext) or ext in path for ext in (".css", ".js", ".jpg"))
        if is_static:
            if url in self.store:                                   # cache HIT
                return FakeResponse(self.store[url], {"x-cache": "hit", "age": "5"})
            body = self.SENSITIVE if authed else self.ANON          # origin serves base page
            self.store[url] = body                                  # cache stores the static URL
            return FakeResponse(body, {"x-cache": "miss"})
        return FakeResponse(self.SENSITIVE if authed else self.ANON, {"x-cache": "miss"})


class SafeStaticSession(DeceptionCacheSession):
    """Not vulnerable: the origin 404s the static-suffix URL (does not path-confuse)."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        path = url.split("?", 1)[0]
        if any(ext in path for ext in (".css", ".js", ".jpg")):
            return FakeResponse("not found", {"x-cache": "miss"}, status=404)
        authed = self._authed(headers)
        return FakeResponse(self.SENSITIVE if authed else self.ANON, {"x-cache": "miss"})


_SETTINGS = {
    "TARGET_DOMAIN": "shop.test",
    "AUTH_PROFILE": {"authType": "cookie", "authValue": "session=abc", "reconEnabled": True},
}
_URL = "https://shop.test/account"
_ORACLE = {"signals": ["x-cache"]}


def test_deception_confirmed_when_authed_page_leaks_from_cache():
    f = deception.deception_probe(_URL, _ORACLE, DeceptionCacheSession(), _SETTINGS, timeout=2)
    assert f is not None
    assert f["technique"] == "cache_deception"
    assert f["impact"] == "deception"
    assert f["detection_mode"] == "deception"
    assert f["confidence_tier"] == "Confirmed"
    assert ".css" in f["endpoint_url"] or ".js" in f["endpoint_url"] or ".jpg" in f["endpoint_url"]


def test_no_finding_without_auth_profile():
    # No session -> deception is unprovable natively -> None.
    assert deception.deception_probe(_URL, _ORACLE, DeceptionCacheSession(), {}, timeout=2) is None


def test_no_finding_when_origin_404s_static_suffix():
    assert deception.deception_probe(_URL, _ORACLE, SafeStaticSession(), _SETTINGS, timeout=2) is None


def test_out_of_scope_host_gets_no_session():
    # The auth profile is scoped to shop.test; a different host gets no auth -> None.
    f = deception.deception_probe("https://other.test/account", _ORACLE,
                                  DeceptionCacheSession(), _SETTINGS, timeout=2)
    assert f is None


class PrivateAccountSession(DeceptionCacheSession):
    """The account page itself is marked `private, no-store` (as nearly every account
    page is), so the cache keeps the base page out; only the static-suffix URL the
    attacker crafts gets stored, which is the whole deception."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False, **kwargs):
        resp = super().get(url, headers, timeout, verify, allow_redirects, **kwargs)
        path = url.split("?", 1)[0]
        if not any(ext in path for ext in (".css", ".js", ".jpg")):
            resp.headers["cache-control"] = "private, no-store"
        return resp


def test_scanner_probes_deception_on_a_private_account_page():
    # The oracle rightly finds the private base page not cacheable; the scan must still
    # run the deception probe on it instead of skipping the URL.
    from recon.cache_scan import scanner

    orig_s, orig_w = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
    scanner._build_retry_session = lambda *a, **k: PrivateAccountSession()
    scanner.wcvs_runner.run_wcvs = lambda *a, **k: []
    try:
        rd = {"http_probe": {"by_url": {_URL: {"url": _URL, "status_code": 200}}}, "metadata": {}}
        cs = scanner.run_cache_scan(rd, {**_SETTINGS, "WEB_CACHE_POISON_ENABLED": True})["cache_scan"]
    finally:
        scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_s, orig_w
    assert cs["by_target"][_URL]["oracle"]["cacheable"] is False
    assert [f["impact"] for f in cs["findings"]] == ["deception"]

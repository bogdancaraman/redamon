"""crt.name as the fallback for crt.sh (domain_recon.query_crtsh / query_crtname).

crt.sh answers 502 for hours at a stretch. When it gives no answer the names
come from crt.name, whose free tier is 100 requests per IP per day - so most of
what is pinned here is what must NOT reach the network: a second lookup for a
name already asked this run, a lookup after the quota is spent, a lookup while
crt.sh is answering. The rest is what a third party's answer may not do to the
scan: raise, fill memory, or put names outside the root into the graph.

Every HTTP call is routed through ``_Net`` by URL; nothing here opens a socket.
"""
from __future__ import annotations

import gzip
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import domain_recon as dr
from recon.main_recon_modules import origin_discovery as od

# The bodies crt.name really sends when it refuses a name.
NOT_AN_APEX = "invalid apex: not an apex (eTLD+1 is example.com)\n"
PUBLIC_SUFFIX = 'invalid apex: publicsuffix: cannot derive eTLD+1 for domain "co.uk"\n'
TOO_LARGE = "apex too large: example.com has too many records to serve via this endpoint\n"

TEXT = {"Content-Type": "text/plain; charset=utf-8"}


class _Resp:
    """A response that can only be read the way a streamed one is.

    There is deliberately no ``.text`` / ``.content``: reading a third party's
    body whole is the thing the streaming code exists to avoid.
    """

    def __init__(self, status=200, body="", headers=None, data=None, json_error=False, chunk=None):
        self.status_code = status
        self.body = body.encode() if isinstance(body, str) else body
        self.headers = CaseInsensitiveDict(headers or {})
        self._data = data
        self._json_error = json_error
        self._chunk = chunk
        self.read = 0          # bytes handed out so far
        self.closed = False

    def json(self):
        if self._json_error:
            raise ValueError("Expecting value: line 1 column 1 (char 0)")
        return self._data

    def iter_content(self, chunk_size=1):
        step = self._chunk or chunk_size
        for start in range(0, len(self.body), step):
            piece = self.body[start:start + step]
            self.read += len(piece)
            yield piece

    def close(self):
        self.closed = True


def _crtname_ok(*names, remaining=None, chunk=None):
    headers = dict(TEXT)
    if remaining is not None:
        headers.update({"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": str(remaining)})
    return _Resp(200, "".join(f"{n}\n" for n in names), headers=headers, chunk=chunk)


def _crtsh_ok(*names):
    return _Resp(200, data=[{"name_value": n} for n in names])


class _Net:
    """Answers ``session.get`` by URL and records every request that was made.

    ``crtsh`` / ``crtname`` are each a response, an exception to raise, or a
    callable taking the requested name and returning either.
    """

    def __init__(self, crtsh=None, crtname=None):
        self.crtsh = crtsh if crtsh is not None else _Resp(502)
        self.crtname = crtname if crtname is not None else _crtname_ok()
        self.calls = []
        self._lock = threading.Lock()

    def session(self):
        sess = mock.MagicMock()
        sess.get.side_effect = self._get
        return sess

    def _get(self, url, params=None, timeout=None, stream=False, **kwargs):
        if url.startswith("https://crt.sh/"):
            service, name, answer = "crtsh", url, self.crtsh
        elif url == "https://crt.name/v1/search":
            service, name, answer = "crtname", (params or {}).get("apex"), self.crtname
        else:
            raise AssertionError(f"unexpected outbound URL: {url}")
        with self._lock:
            self.calls.append({"service": service, "name": name, "params": dict(params or {}),
                               "timeout": timeout, "stream": stream})
        if callable(answer):
            answer = answer(name)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def asked(self, service):
        return [c["name"] for c in self.calls if c["service"] == service]

    def patch(self):
        return mock.patch.object(dr.requests, "Session", side_effect=self.session)


def _open_crtsh_breaker():
    breaker = cb.get_breaker("subsrc:crtsh", label="Subdomains", threshold=cb.INTERNAL_THRESHOLD)
    for _ in range(cb.INTERNAL_THRESHOLD):
        breaker.record(cb.Outcome.TRANSIENT, detail="HTTP 502")
    assert cb.is_open("subsrc:crtsh")


class TestWhenTheFallbackRuns:
    def test_an_answering_crtsh_never_touches_crtname(self):
        net = _Net(crtsh=_crtsh_ok("www.example.com", "api.example.com"))
        with net.patch():
            out = dr.query_crtsh("example.com", settings={})
        assert out == {"www.example.com": {"crt.sh"}, "api.example.com": {"crt.sh"}}
        assert net.asked("crtname") == []
        assert net.asked("crtsh") == ["https://crt.sh/?q=%.example.com&output=json"]

    def test_an_empty_crtsh_answer_is_an_answer_not_a_failure(self):
        # "No certificates for this domain" must not spend a crt.name request.
        net = _Net(crtsh=_crtsh_ok())
        with net.patch():
            out = dr.query_crtsh("example.com", settings={})
        assert out == {}
        assert net.asked("crtname") == []

    def test_a_502_is_answered_by_crtname(self):
        net = _Net(crtsh=_Resp(502), crtname=_crtname_ok("www.example.com", "mail.example.com"))
        with net.patch():
            out = dr.query_crtsh("example.com", settings={})
        assert out == {"www.example.com": {"crt.name"}, "mail.example.com": {"crt.name"}}
        call = next(c for c in net.calls if c["service"] == "crtname")
        assert call["params"] == {"apex": "example.com"}
        assert call["timeout"] == dr.CRTNAME_TIMEOUT_S
        # Streamed, or the size ceilings below bound nothing.
        assert call["stream"] is True

    def test_a_timeout_is_answered_by_crtname(self):
        net = _Net(crtsh=requests.exceptions.ReadTimeout("read timed out"),
                   crtname=_crtname_ok("www.example.com"))
        with net.patch():
            out = dr.query_crtsh("example.com", settings={})
        assert out == {"www.example.com": {"crt.name"}}

    def test_a_200_that_is_not_json_is_answered_by_crtname(self):
        # crt.sh serves an HTML error page with a 200 when its database is behind.
        net = _Net(crtsh=_Resp(200, json_error=True), crtname=_crtname_ok("www.example.com"))
        with net.patch():
            out = dr.query_crtsh("example.com", settings={})
        assert out == {"www.example.com": {"crt.name"}}

    def test_a_paused_crtsh_is_answered_by_crtname_without_a_crtsh_call(self):
        # The case the fallback exists for: crt.sh down for the rest of the run.
        _open_crtsh_breaker()
        net = _Net(crtname=_crtname_ok("www.example.com"))
        with net.patch():
            out = dr.query_crtsh("example.com", settings={})
        assert out == {"www.example.com": {"crt.name"}}
        assert net.asked("crtsh") == []

    def test_switching_crtsh_off_switches_the_fallback_off(self):
        net = _Net(crtname=_crtname_ok("www.example.com"))
        with net.patch():
            out = dr.query_crtsh("example.com", settings={"CRTSH_ENABLED": False})
        assert out == {}
        assert net.calls == []

    def test_the_legacy_wrapper_gets_the_fallback_too(self):
        net = _Net(crtname=_crtname_ok("www.example.com"))
        with net.patch(), \
             mock.patch.object(dr, "query_hackertarget", return_value={"ht.example.com": {"hackertarget"}}):
            out = dr.get_passive_subdomains("example.com", None, settings={})
        assert out == {"www.example.com": {"crt.name"}, "ht.example.com": {"hackertarget"}}


class TestWhatComesBack:
    def test_only_valid_hostnames_under_the_root_are_kept(self):
        lines = [
            "example.com",                   # the root itself
            "WWW.Example.com",               # case is folded
            "  spaced.example.com  ",        # whitespace is trimmed
            "a.b.c.example.com",
            "_dmarc.example.com",
            "",
            "*.example.com",                 # a wildcard is not a host
            "notexample.com",                # shares the suffix text, not the domain
            "example.com.evil.test",
            "other.test",
            "bad host.example.com",
            "semi;colon.example.com",
            "double..dot.example.com",
            ".leading.example.com",
            ("a" * 250) + ".example.com",    # longer than a DNS name can be
            '{"sub":"json.example.com"}',
            "<html>example.com</html>",
        ]
        net = _Net(crtname=_Resp(200, "\n".join(lines) + "\n", headers=TEXT))
        with net.patch():
            out = dr.query_crtname("example.com", settings={})
        assert list(out) == ["example.com", "www.example.com", "spaced.example.com",
                             "a.b.c.example.com", "_dmarc.example.com"]
        assert all(sources == {"crt.name"} for sources in out.values())

    def test_a_name_that_is_not_ascii_is_dropped_not_rewritten(self):
        # Dropping the bytes that do not decode would turn this into the
        # different, plausible host "bcher.example.com".
        body = "bücher.example.com\nwww.example.com\n".encode("utf-8")
        net = _Net(crtname=_Resp(200, body, headers=TEXT))
        with net.patch():
            assert list(dr.query_crtname("example.com", settings={})) == ["www.example.com"]

    def test_names_come_back_once_in_the_order_served(self):
        net = _Net(crtname=_crtname_ok("z.example.com", "a.example.com", "z.example.com", "m.example.com"))
        with net.patch():
            out = dr.query_crtname("example.com", settings={})
        assert list(out) == ["z.example.com", "a.example.com", "m.example.com"]

    @pytest.mark.parametrize("chunk", [1, 7, 64, 65536])
    def test_a_name_split_across_chunks_is_read_whole(self, chunk):
        names = [f"host{i}.example.com" for i in range(40)]
        net = _Net(crtname=_crtname_ok(*names, chunk=chunk))
        with net.patch():
            assert list(dr.query_crtname("example.com", settings={})) == names

    def test_crlf_lines_and_a_last_line_with_no_newline(self):
        net = _Net(crtname=_Resp(200, b"a.example.com\r\nb.example.com\r\nc.example.com", headers=TEXT))
        with net.patch():
            out = dr.query_crtname("example.com", settings={})
        assert list(out) == ["a.example.com", "b.example.com", "c.example.com"]

    def test_the_root_is_normalised_before_it_is_asked(self):
        net = _Net(crtname=_crtname_ok("www.example.com"))
        with net.patch():
            out = dr.query_crtname(" Example.COM. ", settings={})
        assert net.asked("crtname") == ["example.com"]
        assert out == {"www.example.com": {"crt.name"}}

    def test_the_crtsh_ceiling_keeps_the_first_names_served(self):
        net = _Net(crtname=_crtname_ok("d.example.com", "b.example.com", "a.example.com", "c.example.com"))
        with net.patch():
            capped = dr.query_crtname("example.com", settings={"CRTSH_MAX_RESULTS": 2})
            # The cap is the caller's, not the cache's: a later caller with a
            # higher ceiling still gets every name, and no second request.
            full = dr.query_crtname("example.com", settings={"CRTSH_MAX_RESULTS": 50})
        assert list(capped) == ["d.example.com", "b.example.com"]
        assert len(full) == 4
        assert net.asked("crtname") == ["example.com"]

    @pytest.mark.parametrize("headers,body", [
        ({"Content-Type": "text/html; charset=utf-8"}, "<html><body>Sign in to the network</body></html>"),
        ({"Content-Type": "application/json"}, '[{"sub":"www.example.com"}]'),
    ])
    def test_a_200_that_is_not_the_name_list_is_a_failure_not_an_empty_answer(self, headers, body):
        # A captive portal answers 200 too. Read as a name list it has no valid
        # line, and "no names" would be cached for the rest of the run.
        net = _Net(crtname=_Resp(200, body, headers=headers))
        with net.patch():
            assert dr.query_crtname("example.com", settings={}) == {}
            net.crtname = _crtname_ok("www.example.com")
            assert dr.query_crtname("example.com", settings={}) == {"www.example.com": {"crt.name"}}
        assert net.asked("crtname") == ["example.com", "example.com"]

    @pytest.mark.parametrize("body,expected", [("www.example.com\n", ["www.example.com"]), ("", [])])
    def test_a_200_that_declares_no_type_is_still_an_answer(self, body, expected):
        # An empty body is how crt.name says "no names". Were a missing header a
        # failure, every domain it has never seen would be asked again on each
        # call and three of them would pause the source.
        net = _Net(crtname=_Resp(200, body))
        with net.patch():
            assert list(dr.query_crtname("example.com", settings={})) == expected
            assert list(dr.query_crtname("example.com", settings={})) == expected
        assert net.asked("crtname") == ["example.com"]


class TestAnAnswerTooLargeToUse:
    def test_a_413_is_cached_and_never_asked_again(self):
        # crt.name declines a domain with more names than it serves at once.
        # Retrying spends the quota on the same refusal.
        net = _Net(crtname=_Resp(413, TOO_LARGE, headers=TEXT))
        with net.patch():
            for _ in range(4):
                assert dr.query_crtname("example.com", settings={}) == {}
        assert net.asked("crtname") == ["example.com"]

    def test_413s_do_not_pause_crtname_for_the_other_roots(self):
        net = _Net(crtname=_Resp(413, TOO_LARGE, headers=TEXT))
        with net.patch():
            for root in ("a.test", "b.test", "c.test", "d.test"):
                dr.query_crtname(root, settings={})
            assert not cb.is_open("subsrc:crtname")
            net.crtname = _crtname_ok("www.example.com")
            assert dr.query_crtname("example.com", settings={}) == {"www.example.com": {"crt.name"}}

    def test_a_413_is_reported_as_too_many_names_not_as_none(self, capsys):
        net = _Net(crtname=_Resp(413, TOO_LARGE, headers=TEXT))
        with net.patch():
            dr.query_crtname("example.com", settings={})
        assert "[-][crt.name] HTTP 413 - this domain has too many names" in capsys.readouterr().out

    def test_reading_stops_at_the_name_ceiling(self, monkeypatch, capsys):
        monkeypatch.setattr(dr, "CRTNAME_MAX_NAMES", 3)
        names = [f"host{i:05d}.example.com" for i in range(20000)]
        resp = _crtname_ok(*names, chunk=64)
        net = _Net(crtname=resp)
        with net.patch():
            out = dr.query_crtname("example.com", settings={})
            again = dr.query_crtname("example.com", settings={})
        assert list(out) == names[:3]
        assert resp.read < 1024 < len(resp.body)      # the rest was never downloaded
        assert again == out and net.asked("crtname") == ["example.com"]
        assert "kept its first 3 names" in capsys.readouterr().out

    def test_reading_stops_at_the_byte_ceiling(self, monkeypatch):
        # A subdomain root under a huge domain: almost no line is kept, so only
        # the byte ceiling can end the read.
        monkeypatch.setattr(dr, "CRTNAME_MAX_BYTES", 2000)
        lines = ["first.app.example.com"] + [f"other{i:05d}.example.com" for i in range(20000)]
        resp = _crtname_ok(*lines, chunk=100)

        def answer(name):
            return _Resp(400, NOT_AN_APEX, headers=TEXT) if name == "app.example.com" else resp

        net = _Net(crtname=answer)
        with net.patch():
            out = dr.query_crtname("app.example.com", settings={})
        assert list(out) == ["first.app.example.com"]
        assert resp.read <= 2000 + 100

    def test_a_line_that_never_ends_cannot_outgrow_the_byte_ceiling(self, monkeypatch):
        monkeypatch.setattr(dr, "CRTNAME_MAX_BYTES", 1000)
        resp = _Resp(200, b"a" * 500_000, headers=TEXT, chunk=100)
        net = _Net(crtname=resp)
        with net.patch():
            assert dr.query_crtname("example.com", settings={}) == {}
        assert resp.read <= 1000 + 100

    def test_an_answer_still_arriving_at_the_deadline_is_a_failure(self, monkeypatch):
        monkeypatch.setattr(dr, "CRTNAME_DEADLINE_S", -1)
        net = _Net(crtname=_crtname_ok("www.example.com"))
        with net.patch():
            assert dr.query_crtname("example.com", settings={}) == {}
            monkeypatch.setattr(dr, "CRTNAME_DEADLINE_S", 90)
            # Not cached: a slow link is not "this domain has one name".
            assert dr.query_crtname("example.com", settings={}) == {"www.example.com": {"crt.name"}}
        assert net.asked("crtname") == ["example.com", "example.com"]

    def test_only_the_head_of_a_refusal_is_read(self):
        refusal = _Resp(400, NOT_AN_APEX.encode() + b"x" * 500_000, headers=TEXT)

        def answer(name):
            return refusal if name == "app.example.com" else _crtname_ok("api.app.example.com")

        net = _Net(crtname=answer)
        with net.patch():
            out = dr.query_crtname("app.example.com", settings={})
        assert out == {"api.app.example.com": {"crt.name"}}
        assert refusal.read <= 512
        assert refusal.closed


class TestARootThatIsASubdomain:
    def _answer(self, name):
        if name == "app.example.com":
            return _Resp(400, NOT_AN_APEX, headers=TEXT)
        return _crtname_ok("app.example.com", "api.app.example.com", "mail.example.com", "example.com")

    def test_the_parent_crtname_names_is_asked_and_only_the_roots_names_are_kept(self):
        net = _Net(crtname=self._answer)
        with net.patch():
            out = dr.query_crtname("app.example.com", settings={})
        assert net.asked("crtname") == ["app.example.com", "example.com"]
        # mail.example.com and example.com are siblings/parents of the root: out
        # of scope, and they must not come back to be filed as external domains.
        assert sorted(out) == ["api.app.example.com", "app.example.com"]

    def test_the_answer_is_cached_under_the_root_that_was_asked(self):
        net = _Net(crtname=self._answer)
        with net.patch():
            first = dr.query_crtname("app.example.com", settings={})
            second = dr.query_crtname("app.example.com", settings={})
        assert first == second
        assert len(net.asked("crtname")) == 2   # the refusal and its retry, once

    def test_a_named_parent_that_is_not_a_parent_is_not_asked(self):
        net = _Net(crtname=_Resp(400, "invalid apex: not an apex (eTLD+1 is attacker.test)", headers=TEXT))
        with net.patch():
            out = dr.query_crtname("app.example.com", settings={})
        assert out == {}
        assert net.asked("crtname") == ["app.example.com"]

    def test_a_bare_tld_is_never_taken_as_the_parent(self):
        net = _Net(crtname=_Resp(400, "invalid apex: not an apex (eTLD+1 is com)", headers=TEXT))
        with net.patch():
            dr.query_crtname("app.example.com", settings={})
        assert net.asked("crtname") == ["app.example.com"]

    def test_a_refusal_with_no_parent_is_cached_and_never_asked_again(self):
        # A public suffix (origin discovery reduces acme.com.co to com.co): the
        # refusal is charged against the quota, so it is paid for once.
        net = _Net(crtname=_Resp(400, PUBLIC_SUFFIX, headers=TEXT))
        with net.patch():
            assert dr.query_crtname("co.uk", settings={}) == {}
            assert dr.query_crtname("co.uk", settings={}) == {}
        assert net.asked("crtname") == ["co.uk"]

    def test_a_parent_that_is_refused_too_is_cached(self):
        net = _Net(crtname=lambda name: _Resp(400, NOT_AN_APEX, headers=TEXT))
        with net.patch():
            assert dr.query_crtname("app.example.com", settings={}) == {}
            assert dr.query_crtname("app.example.com", settings={}) == {}
        assert net.asked("crtname") == ["app.example.com", "example.com"]

    def test_refusals_do_not_pause_the_source(self):
        # A 400 is an answer about the name. Four of them must leave crt.name
        # available for the next root.
        net = _Net(crtname=lambda name: _Resp(400, PUBLIC_SUFFIX, headers=TEXT))
        with net.patch():
            for root in ("co.uk", "com.au", "co.nz", "co.za"):
                dr.query_crtname(root, settings={})
        assert not cb.is_open("subsrc:crtname")


class TestARootNotWorthARequest:
    @pytest.mark.parametrize("root", [
        "", None, "localhost", "1.1", "10.0.0.1", "2001:db8::1", "example..com",
        "bad host.example.com", "example.com/path", "exa_mple.com:8080", ("a" * 250) + ".com",
    ])
    def test_nothing_is_asked(self, root):
        net = _Net(crtname=_crtname_ok("www.example.com"))
        with net.patch():
            assert dr.query_crtname(root, settings={}) == {}
        assert net.calls == []


class TestTheDailyQuota:
    def test_one_request_per_root_per_run(self):
        net = _Net(crtname=_crtname_ok("www.example.com"))
        with net.patch():
            first = dr.query_crtsh("example.com", settings={})
            for _ in range(5):
                assert dr.query_crtsh("example.com", settings={}) == first
        assert net.asked("crtname") == ["example.com"]

    def test_an_empty_answer_is_cached_too(self):
        net = _Net(crtname=_crtname_ok())
        with net.patch():
            for _ in range(3):
                assert dr.query_crtname("example.com", settings={}) == {}
        assert net.asked("crtname") == ["example.com"]

    def test_a_failure_is_not_cached(self):
        net = _Net(crtname=_Resp(503))
        with net.patch():
            assert dr.query_crtname("example.com", settings={}) == {}
            net.crtname = _crtname_ok("www.example.com")
            assert dr.query_crtname("example.com", settings={}) == {"www.example.com": {"crt.name"}}
        assert net.asked("crtname") == ["example.com", "example.com"]

    def test_concurrent_callers_for_one_root_spend_one_request(self):
        # Origin discovery asks for one registrable domain from many host threads.
        def slow(name):
            time.sleep(0.05)
            return _crtname_ok("www.example.com")

        net = _Net(crtname=slow)
        start = threading.Barrier(8)

        def call():
            start.wait(timeout=5)
            return dr.query_crtname("example.com", settings={})

        with net.patch(), ThreadPoolExecutor(max_workers=8) as pool:
            results = [f.result(timeout=10) for f in [pool.submit(call) for _ in range(8)]]
        assert net.asked("crtname") == ["example.com"]
        assert all(r == {"www.example.com": {"crt.name"}} for r in results)

    def test_a_spent_quota_stops_the_source_for_the_run(self, capsys):
        spent = _Resp(429, "rate limit exceeded",
                      headers={"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "0"})
        net = _Net(crtname=spent)
        with net.patch():
            assert dr.query_crtname("a.test", settings={}) == {}
            assert cb.is_fatal("subsrc:crtname")
            for root in ("b.test", "c.test", "d.test"):
                assert dr.query_crtname(root, settings={}) == {}
        assert net.asked("crtname") == ["a.test"]
        out = capsys.readouterr().out
        assert "[!][crt.name] HTTP 429 - daily quota reached" in out
        assert "stopped for the rest of this run" in out
        # The later roots are told why, not that there were "repeated failures".
        assert out.count("[-][crt.name] daily quota reached - skipping") == 3
        assert "repeated failures" not in out

    def test_a_429_that_is_not_the_quota_only_pauses_after_two_in_a_row(self):
        cb.set_clock(sleep=lambda seconds: None)   # the shared 429 pause, not slept out
        net = _Net(crtname=_Resp(429))
        with net.patch():
            dr.query_crtname("a.test", settings={})
            assert not cb.is_open("subsrc:crtname")
            dr.query_crtname("b.test", settings={})
        assert cb.is_open("subsrc:crtname")
        assert not cb.is_fatal("subsrc:crtname")

    def test_repeated_failures_pause_crtname(self, capsys):
        net = _Net(crtname=_Resp(502))
        with net.patch():
            for root in ("a.test", "b.test", "c.test"):
                dr.query_crtname(root, settings={})
            assert cb.is_open("subsrc:crtname")
            dr.query_crtname("d.test", settings={})
        assert net.asked("crtname") == ["a.test", "b.test", "c.test"]
        assert "[-][crt.name] paused this run after repeated failures - skipping" in capsys.readouterr().out

    def test_a_paused_crtname_is_probed_once_after_the_cooldown_and_resumes(self):
        clock = {"now": 1000.0}
        cb.set_clock(now=lambda: clock["now"], sleep=lambda seconds: None)
        net = _Net(crtname=_Resp(502))
        with net.patch():
            for root in ("a.test", "b.test", "c.test"):
                dr.query_crtname(root, settings={})
            net.crtname = _crtname_ok("www.example.com")
            clock["now"] += cb.COOLDOWN_S - 1
            assert dr.query_crtname("example.com", settings={}) == {}        # still paused
            assert len(net.asked("crtname")) == 3
            clock["now"] += 2
            assert dr.query_crtname("example.com", settings={}) == {"www.example.com": {"crt.name"}}
        assert not cb.is_open("subsrc:crtname")

    def test_a_404_is_a_fault_of_the_source_not_an_answer(self):
        # An unknown name answers 200, so a 404 means the endpoint moved. Cached
        # as "no names" it would cost one request per root, forever unnoticed.
        net = _Net(crtname=_Resp(404, "404 page not found", headers=TEXT))
        with net.patch():
            for root in ("a.test", "b.test", "c.test", "d.test", "e.test"):
                assert dr.query_crtname(root, settings={}) == {}
        assert cb.is_open("subsrc:crtname")
        assert net.asked("crtname") == ["a.test", "b.test", "c.test"]

    def test_a_200_reporting_no_requests_left_is_used_and_is_the_last_one(self, capsys):
        net = _Net(crtname=_crtname_ok("www.example.com", remaining=0))
        with net.patch():
            assert dr.query_crtname("example.com", settings={}) == {"www.example.com": {"crt.name"}}
            # The answer that came with it is still served from the cache...
            assert dr.query_crtname("example.com", settings={}) == {"www.example.com": {"crt.name"}}
            # ...and the request certain to be refused is never sent.
            assert dr.query_crtname("other.test", settings={}) == {}
        assert net.asked("crtname") == ["example.com"]
        assert cb.is_fatal("subsrc:crtname")
        assert "[-][crt.name] daily quota reached - skipping" in capsys.readouterr().out

    @pytest.mark.parametrize("spent", [
        _Resp(429, headers={"X-RateLimit-Remaining": "0"}),
        _crtname_ok("www.example.com", remaining=0),
    ])
    def test_the_quota_stop_holds_with_the_breakers_off(self, monkeypatch, spent):
        # With the switch off no breaker can refuse a call, and each of the
        # lookups a run makes would be sent, refused and logged.
        monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
        net = _Net(crtname=spent)
        with net.patch():
            for root in ("a.test", "b.test", "c.test", "d.test"):
                dr.query_crtname(root, settings={})
        assert net.asked("crtname") == ["a.test"]

    def test_with_both_sources_down_a_later_root_makes_no_http_call(self):
        net = _Net(crtsh=_Resp(502), crtname=_Resp(502))
        with net.patch():
            for root in ("a.test", "b.test", "c.test"):
                assert dr.query_crtsh(root, settings={}) == {}
            before = len(net.calls)
            assert dr.query_crtsh("d.test", settings={}) == {}
        assert len(net.calls) == before

    def test_the_cache_still_guards_the_quota_with_the_breakers_off(self, monkeypatch):
        monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
        net = _Net(crtsh=_Resp(502), crtname=_crtname_ok("www.example.com"))
        with net.patch():
            for _ in range(4):
                assert dr.query_crtsh("example.com", settings={}) == {"www.example.com": {"crt.name"}}
        assert net.asked("crtname") == ["example.com"]


class TestWhatIsLogged:
    def test_the_requests_left_today_are_reported(self, capsys):
        net = _Net(crtname=_crtname_ok("www.example.com", remaining=87))
        with net.patch():
            dr.query_crtsh("example.com", settings={})
        out = capsys.readouterr().out
        assert "[!][crt.sh] HTTP 502" in out
        assert "[+][crt.name] Found 1 subdomains (87 requests left today)" in out

    def test_a_missing_quota_header_is_left_out_not_invented(self, capsys):
        net = _Net(crtname=_crtname_ok("www.example.com"))
        with net.patch():
            dr.query_crtname("example.com", settings={})
        out = capsys.readouterr().out
        assert "[+][crt.name] Found 1 subdomains\n" in out
        assert "left today" not in out

    @pytest.mark.parametrize("status", [400, 413, 429, 500])
    def test_a_response_body_is_never_logged(self, capsys, status):
        marker = "BODY-MARKER-5f1c"
        net = _Net(crtname=_Resp(status, f"{marker} (eTLD+1 is unrelated.test)", headers=TEXT))
        with net.patch():
            dr.query_crtname("app.example.com", settings={})
        assert marker not in capsys.readouterr().out


class TestItNeverRaises:
    def test_a_network_error(self):
        net = _Net(crtname=requests.exceptions.ConnectionError("connection refused"))
        with net.patch():
            assert dr.query_crtsh("example.com", settings={}) == {}

    def test_a_connection_that_drops_mid_answer(self):
        class _Dropping(_Resp):
            def iter_content(self, chunk_size=1):
                yield b"www.example.com\nmail.exa"
                raise requests.exceptions.ChunkedEncodingError("connection broken")

        net = _Net(crtname=_Dropping(200, headers=TEXT))
        with net.patch():
            # Half an answer is not an answer: nothing kept, nothing cached.
            assert dr.query_crtname("example.com", settings={}) == {}
            net.crtname = _crtname_ok("www.example.com")
            assert dr.query_crtname("example.com", settings={}) == {"www.example.com": {"crt.name"}}

    def test_a_faulting_run_cache(self):
        net = _Net(crtname=_crtname_ok("www.example.com"))
        with net.patch(), mock.patch.object(cb, "run_cache", side_effect=RuntimeError("boom")):
            assert dr.query_crtsh("example.com", settings={}) == {}

    @pytest.mark.parametrize("settings", [
        {"CRTSH_MAX_RESULTS": None}, {"CRTSH_MAX_RESULTS": "many"}, ["not", "a", "dict"],
    ])
    def test_settings_of_an_unexpected_type(self, settings):
        net = _Net(crtname=_crtname_ok("www.example.com", "mail.example.com"))
        with net.patch():
            assert dr.query_crtname("example.com", settings=settings) == {}

    def test_a_response_of_an_unexpected_type(self):
        # What a bare mock hands back for every attribute.
        cb.set_clock(sleep=lambda seconds: None)   # the 429 below sets a shared pause
        resp = mock.MagicMock()
        resp.status_code = 400
        net = _Net(crtname=resp)
        with net.patch():
            assert dr.query_crtname("app.example.com", settings={}) == {}
        resp.status_code = 429
        with net.patch():
            assert dr.query_crtname("other.example.com", settings={}) == {}
        assert not cb.is_fatal("subsrc:crtname")   # an unreadable header is not "0 left"
        resp.status_code = 200
        with net.patch():
            assert dr.query_crtname("third.example.com", settings={}) == {}

    @pytest.mark.parametrize("header,expected", [
        ("12", 12), (" 0 ", 0), ("0, 0", 0), ("0.0", 0), ("7;w=86400", 7),
        ("-3", None), ("", None), ("many", None), (None, None),
    ])
    def test_the_quota_header_is_parsed_or_ignored(self, header, expected):
        headers = {} if header is None else {"x-ratelimit-remaining": header}
        assert dr._crtname_remaining(_Resp(200, headers=headers)) == expected


class _Raw:
    """urllib3's response as far as the reader uses it: ``read1`` and nothing else."""

    def __init__(self, *pieces):
        self.pieces = list(pieces)
        self.calls = []

    def read1(self, amt=None, decode_content=None):
        self.calls.append((amt, decode_content))
        return self.pieces.pop(0) if self.pieces else b""


class _RawOnly(_Resp):
    """A response whose body can only be reached through ``raw.read1``."""

    def __init__(self, status, *pieces, headers=None):
        super().__init__(status, headers=headers)
        self.raw = _Raw(*pieces)

    def iter_content(self, chunk_size=1):
        raise AssertionError("iter_content waits for a full chunk; read1 was available")


class TestReadingWithoutWaitingForAFullChunk:
    def test_read1_is_used_when_the_response_has_it(self):
        resp = _RawOnly(200, b"a.example.com\nb.exa", b"mple.com\n", b"c.example.com", headers=TEXT)
        net = _Net(crtname=resp)
        with net.patch():
            out = dr.query_crtname("example.com", settings={})
        assert list(out) == ["a.example.com", "b.example.com", "c.example.com"]
        # Decoded, or a gzip answer would be read as bytes that match no name.
        assert resp.raw.calls and all(decode is True for _amt, decode in resp.raw.calls)

    def test_a_none_from_read1_ends_the_answer(self):
        resp = _RawOnly(200, b"a.example.com\n", None, b"never.example.com\n", headers=TEXT)
        net = _Net(crtname=resp)
        with net.patch():
            assert list(dr.query_crtname("example.com", settings={})) == ["a.example.com"]

    def test_the_refusal_is_read_through_read1_too(self):
        refusal = _RawOnly(400, NOT_AN_APEX.encode(), headers=TEXT)

        def answer(name):
            return refusal if name == "app.example.com" else _crtname_ok("api.app.example.com")

        net = _Net(crtname=answer)
        with net.patch():
            assert dr.query_crtname("app.example.com", settings={}) == {"api.app.example.com": {"crt.name"}}
        assert refusal.raw.calls == [(512, True)]

    def test_a_body_that_is_not_bytes_is_a_failure(self):
        resp = _RawOnly(200, "a.example.com\n", headers=TEXT)
        net = _Net(crtname=resp)
        with net.patch():
            assert dr.query_crtname("example.com", settings={}) == {}
            net.crtname = _crtname_ok("www.example.com")
            assert dr.query_crtname("example.com", settings={}) == {"www.example.com": {"crt.name"}}


class _Peer:
    """A loopback HTTP server, so the real requests/urllib3 stack does the reading.

    The fakes above stand in for the response object; they cannot show what
    urllib3 does with a gzip body, a chunked one, or one that arrives a byte
    at a time. ``respond(handler, apex)`` writes the whole response.
    """

    def __init__(self, respond):
        peer = self
        self.paths = []
        self.stopping = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                peer.paths.append(self.path)
                apex = self.path.partition("apex=")[2]
                try:
                    respond(self, apex)
                except OSError:
                    pass   # the client hung up, which is what the deadline test wants

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1/search"
        # The short poll keeps shutdown() from adding half a second per test.
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02},
                         daemon=True).start()

    def close(self):
        self.stopping.set()
        self.server.shutdown()
        self.server.server_close()


def _send(handler, status, body, **headers):
    handler.send_response(status)
    for name, value in {"Content-Type": "text/plain; charset=utf-8",
                        "Content-Length": str(len(body)), **headers}.items():
        handler.send_header(name.replace("_", "-"), value)
    handler.end_headers()
    handler.wfile.write(body)


@pytest.fixture
def peer(monkeypatch):
    peers = []

    def start(respond):
        started = _Peer(respond)
        peers.append(started)
        monkeypatch.setattr(dr, "CRTNAME_URL", started.url)
        return started

    # A proxy in the environment must not be handed the loopback request.
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    yield start
    for started in peers:
        started.close()


class TestThroughTheRealHttpStack:
    def test_a_gzip_chunked_answer_is_decoded(self, peer, capsys):
        # The shape crt.name answers in over HTTP/1.1.
        body = gzip.compress(b"www.example.com\nmail.example.com\nother.test\n")

        def respond(handler, apex):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/plain; charset=utf-8")
            handler.send_header("Content-Encoding", "gzip")
            handler.send_header("Transfer-Encoding", "chunked")
            handler.send_header("X-RateLimit-Remaining", "41")
            handler.end_headers()
            for start in range(0, len(body), 9):
                piece = body[start:start + 9]
                handler.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
            handler.wfile.write(b"0\r\n\r\n")

        started = peer(respond)
        out = dr.query_crtname("example.com", settings={})
        assert list(out) == ["www.example.com", "mail.example.com"]
        assert started.paths == ["/v1/search?apex=example.com"]
        assert "(41 requests left today)" in capsys.readouterr().out

    def test_a_subdomain_root_is_refused_then_answered_through_its_parent(self, peer):
        def respond(handler, apex):
            if apex == "app.example.com":
                _send(handler, 400, NOT_AN_APEX.encode())
            else:
                _send(handler, 200, b"api.app.example.com\nmail.example.com\n")

        started = peer(respond)
        assert dr.query_crtname("app.example.com", settings={}) == {"api.app.example.com": {"crt.name"}}
        assert started.paths == ["/v1/search?apex=app.example.com", "/v1/search?apex=example.com"]

    def test_an_empty_answer_and_a_too_large_refusal_are_both_cached(self, peer):
        def respond(handler, apex):
            if apex == "big.test":
                _send(handler, 413, TOO_LARGE.encode())
            else:
                _send(handler, 200, b"")

        started = peer(respond)
        for _ in range(3):
            assert dr.query_crtname("unknown.test", settings={}) == {}
            assert dr.query_crtname("big.test", settings={}) == {}
        assert started.paths == ["/v1/search?apex=unknown.test", "/v1/search?apex=big.test"]
        assert not cb.is_open("subsrc:crtname")

    def test_a_body_that_trickles_in_is_cut_at_the_deadline(self, peer, monkeypatch):
        # A byte every 50 ms never trips the read timeout. Read in full chunks,
        # the declared 60,000 bytes would hold the call, and the lock every
        # other lookup waits on, for as long as the peer cares to keep sending.
        monkeypatch.setattr(dr, "CRTNAME_TIMEOUT_S", 2)
        monkeypatch.setattr(dr, "CRTNAME_DEADLINE_S", 0.5)

        def respond(handler, apex):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/plain; charset=utf-8")
            handler.send_header("Content-Length", "60000")
            handler.end_headers()
            for byte in (b"www.example.com\n" * 20)[:300]:   # 15 s at most, then hang up
                if started.stopping.is_set():
                    return
                handler.wfile.write(bytes([byte]))
                handler.wfile.flush()
                time.sleep(0.05)
            handler.close_connection = True

        started = peer(respond)
        began = time.monotonic()
        assert dr.query_crtname("example.com", settings={}) == {}
        assert time.monotonic() - began < 8
        # A slow link is not an answer: the names that did arrive are not kept.
        assert len(cb.run_cache("crtname")) == 0


class TestTheCallersOfQueryCrtsh:
    def _discover(self, net, domain, **settings):
        with net.patch(), \
             mock.patch.object(dr, "query_hackertarget", return_value={}), \
             mock.patch.object(dr, "run_subfinder", return_value={f"sf.{domain}"}), \
             mock.patch.object(dr, "run_amass", return_value=set()), \
             mock.patch.object(dr, "run_knockpy", return_value=set()), \
             mock.patch.object(dr, "run_puredns_resolve", side_effect=lambda subs, d, s: subs):
            return dr.discover_subdomains(domain, resolve=False, save_output=False,
                                          settings={"CRTSH_ENABLED": True, **settings})

    def test_subdomain_discovery_merges_the_fallback_names(self):
        net = _Net(crtsh=_Resp(502), crtname=_crtname_ok("www.example.com", "mail.example.com"))
        result = self._discover(net, "example.com")
        assert result["subdomains"] == ["mail.example.com", "sf.example.com", "www.example.com"]
        assert result["external_domains"] == []

    def test_a_subdomain_root_files_no_sibling_as_an_external_domain(self):
        def answer(name):
            if name == "app.example.com":
                return _Resp(400, NOT_AN_APEX, headers=TEXT)
            return _crtname_ok("api.app.example.com", "mail.example.com", "vpn.example.com")

        net = _Net(crtsh=_Resp(502), crtname=answer)
        result = self._discover(net, "app.example.com")
        assert result["subdomains"] == ["api.app.example.com", "sf.app.example.com"]
        assert result["external_domains"] == []

    def test_origin_discovery_resolves_the_fallback_names(self):
        net = _Net(crtsh=_Resp(502), crtname=_crtname_ok("origin.example.com", "www.example.com"))
        ctx = od._RunCtx({"CRTSH_ENABLED": True})
        resolved = []

        def resolve(name):
            resolved.append(name)
            return {"45.33.32.10"}

        with net.patch(), mock.patch.object(od, "_resolve_ips", side_effect=resolve):
            ips = od._discover_via_crtsh("example.com", ctx)
        assert ips == ["45.33.32.10"]
        assert sorted(resolved) == ["origin.example.com", "www.example.com"]

    def test_origin_discovery_reads_the_first_names_served_not_the_first_alphabetically(self):
        # It resolves 500 names at most. Sorted, a domain with thousands would
        # only ever have its digit- and "a"-prefixed names checked for an origin.
        served = [f"n{i:04d}.example.com" for i in range(799, -1, -1)]
        net = _Net(crtsh=_Resp(502), crtname=_crtname_ok(*served))
        ctx = od._RunCtx({"CRTSH_ENABLED": True})
        resolved = set()
        lock = threading.Lock()

        def resolve(name):
            with lock:
                resolved.add(name)
            return set()

        with net.patch(), mock.patch.object(od, "_resolve_ips", side_effect=resolve):
            od._discover_via_crtsh("example.com", ctx)
        assert resolved == set(served[:500])

    def test_origin_discovery_spends_one_request_for_many_hosts_of_a_domain(self):
        # Its own cache keeps only a non-empty IP list, so a domain whose names
        # all sit on a CDN is looked up again for every fronted host. Each of
        # those lookups would otherwise spend a crt.name request.
        _open_crtsh_breaker()
        net = _Net(crtname=_crtname_ok("www.example.com"))
        ctx = od._RunCtx({"CRTSH_ENABLED": True})
        with net.patch(), mock.patch.object(od, "_resolve_ips", return_value=set()):
            for _host in range(6):
                assert ctx.cached("od_crtsh", "example.com",
                                  lambda: od._discover_via_crtsh("example.com", ctx)) == []
        assert net.asked("crtname") == ["example.com"]
        assert net.asked("crtsh") == []

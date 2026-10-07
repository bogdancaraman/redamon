"""
Cache Poisoning Scanner — Cache-buster placement (Phase 2 of the native engine).

A cache buster is useless (or dangerous) if placed in a component the cache
ignores. Before any poison test we run a tiny pre-experiment to learn WHERE the
cache keys, then isolate every test into its own bucket using a keyed component.
This is a safety control, not just an optimisation: wrong placement means either
no isolation (we poison the real entry) or no caching (the test proves nothing).

Strategy: add a unique query parameter and re-request. If the cache treats the
new URL as a fresh entry (MISS then HIT on repeat with that param), the query
string is keyed and is a safe isolation location. A HIT on the very first request
with a never-used value proves the opposite: the cache ignores the query string,
every "isolated" slot is the real entry visitors get, and the URL must not be
tested at all.
"""

from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

import requests

from recon.cache_scan.oracle import response_cache_state
from recon.cache_scan.safety import new_cache_buster_value


def add_cache_buster(url: str, param: str, value: str) -> str:
    """Append ?param=value (or &) to a URL, preserving existing query."""
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[param] = value
    new_query = urlencode(query)
    return urlunparse(parts._replace(query=new_query))


def add_path_param(url: str, name: str, value: str) -> str:
    """Append a matrix / path parameter (``;name=value``) to the path, keeping the
    query. Cache-key normalization abuse: a cache that strips ``;`` path-params from
    its key (but whose origin still reads them) serves the poisoned response to a
    victim who requests the clean path.
    """
    parts = urlparse(url)
    return urlunparse(parts._replace(path=f"{parts.path};{name}={value}"))


def add_path_segment(url: str, segment: str) -> str:
    """Append a path segment BEFORE the query string, preserving the query.

    Framework path-confusion vectors (e.g. Nuxt's ``_payload.json``) must land as a
    real path segment so the request actually reaches the confusion route. Appending
    after ``?rdmncb=`` (the old behaviour) buried the segment inside the query, so the
    route was never exercised and the buster stayed a valid key at the same time.
    """
    parts = urlparse(url)
    base = parts.path if parts.path.endswith("/") else parts.path + "/"
    new_path = base + segment.lstrip("/")
    return urlunparse(parts._replace(path=new_path))


def find_cache_buster(url: str, session: requests.Session, settings: dict,
                      timeout: int = 10, verify_ssl: bool = True) -> dict:
    """Determine a safe isolated cache-buster location for this URL.

    Returns:
      {
        "param": str,        # cache-buster parameter name to use
        "keyed_on_query": bool,   # the query string is proven part of the key
        "isolated": bool,    # False only when the buster is proven unkeyed
      }
    """
    param = settings.get("WEB_CACHE_POISON_CACHE_BUSTER_PARAM") or "rdmncb"

    keyed_on_query = False
    isolated = True
    try:
        # A 5xx/429 makes a try inconclusive: the session's retry re-sends the request
        # onto the slot the failed attempt just filled, and reads back a HIT that says
        # nothing about the key. One origin hiccup must not skip the URL, so retry once
        # on a new value.
        for _ in range(2):
            busted = add_cache_buster(url, param, new_cache_buster_value())
            # First request with the buster: expect a MISS (new entry).
            r1 = session.get(busted, timeout=timeout, verify=verify_ssl, allow_redirects=False)
            if r1.status_code >= 500 or r1.status_code == 429:
                continue
            state1 = response_cache_state(r1)
            # Repeat: expect a HIT if the query string is keyed and cacheable.
            r2 = session.get(busted, timeout=timeout, verify=verify_ssl, allow_redirects=False)
            state2 = response_cache_state(r2)
            if state1 == "hit":
                isolated = False
            elif state1 == "miss" and state2 == "hit":
                keyed_on_query = True
            break
    except requests.RequestException:
        pass

    # Short of that proof (no cache headers, MISS/MISS, a network error) keying can't
    # be decided, and a fresh param per test is the least-harmful option.
    return {"param": param, "keyed_on_query": keyed_on_query, "isolated": isolated}

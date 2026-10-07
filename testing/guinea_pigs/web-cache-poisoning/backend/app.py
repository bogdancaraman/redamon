"""
Guinea-pig backend for the RedAmon Web Cache Poisoning (WCP) module.

A deliberately vulnerable origin server. It sits behind the nginx cache
(see ../nginx/default.conf) and produces responses that exercise EVERY step of
the WCP module pipeline:

  Step 1b  Cache oracle      -> /oracle/*   (each emits a different cache signal)
  Step 3   Hypotheses        -> /poison/*, /diff/*, /fw/*   (the vectors)
  Step 4   Confirmation      -> reflected (canary echoed) + differential (behaviour change)
  Step 5   Scoring/impact    -> open_redirect / stored_xss / reflected_script / dos / reflected / response_change / deception
  Negative controls          -> /safe/*    (must be REJECTED -> proves low false-positive rate)

The backend ONLY shapes the response. Whether a response is *cached* (and therefore
poisonable for other visitors) is decided by nginx in front. The backend logs every
request it actually receives to stderr, so during a scan you can see exactly when a
poison request reached the origin (a cache MISS) versus was served from cache (a HIT,
origin not reached).

Key idea it models: the cache key is URL-only (path + query, so the ?rdmncb= buster
works), while the headers below are UNKEYED but trusted by this backend -> the
poisoning door.
"""

import sys
import time
from email.utils import formatdate
from flask import Flask, request, Response, make_response

app = Flask(__name__)

# Unkeyed request components this backend (wrongly) trusts.
HOST_HEADERS = ["X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Original-Host"]


def log(msg: str) -> None:
    print(f"[backend] {msg}", file=sys.stderr, flush=True)


@app.after_request
def _trace(resp: Response) -> Response:
    # A line per request that actually hit the origin == a cache MISS. During a scan,
    # the absence of a line for a given URL means nginx served it from cache (a HIT).
    log(
        f"{request.method} {request.full_path} "
        f"XFH={request.headers.get('X-Forwarded-Host')} "
        f"XFProto={request.headers.get('X-Forwarded-Proto')} "
        f"XInvoke={request.headers.get('x-invoke-status')} "
        # Tells WCVS's requests from the native engine's (RedAmon-CachePoison/1.0).
        f"UA={(request.headers.get('User-Agent') or '')[:40]} -> {resp.status_code}"
    )
    resp.headers["Server"] = "guinea-pig-wcp/1.0"
    return resp


def cacheable(resp: Response, seconds: int = 60) -> Response:
    """Mark a response cacheable so the nginx cache stores it (shared cache)."""
    resp.headers["Cache-Control"] = f"public, max-age={seconds}"
    return resp


def first_host_header() -> str | None:
    for h in HOST_HEADERS:
        v = request.headers.get(h)
        if v:
            return v
    return None


# --------------------------------------------------------------------------- #
# Landing page — links EVERY endpoint so a crawler (Katana/Hakrawler) discovers
# them and they become resource_enum endpoints the WCP module will target.
# --------------------------------------------------------------------------- #
REGISTRY: list[tuple[str, str, str]] = []


def page(path: str, group: str, desc: str):
    """Register an endpoint for the landing page and define a GET route."""
    REGISTRY.append((path, group, desc))

    def decorator(fn):
        fn_name = f"{fn.__name__}"
        app.add_url_rule(path, endpoint=fn_name, view_func=fn, methods=["GET"])
        return fn
    return decorator


@app.route("/")
def index() -> Response:
    groups: dict[str, list[tuple[str, str]]] = {}
    for path, group, desc in REGISTRY:
        groups.setdefault(group, []).append((path, desc))
    sections = []
    for group, items in groups.items():
        rows = "\n".join(
            f'      <li><a href="{p}">{p}</a> &mdash; {d}</li>' for p, d in items
        )
        sections.append(f"    <h2>{group}</h2>\n    <ul>\n{rows}\n    </ul>")
    body = "\n".join(sections)
    html = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>WCP Guinea Pig</title></head><body>"
        "<h1>RedAmon Web Cache Poisoning Guinea Pig</h1>"
        "<p>Deliberately vulnerable targets for end-to-end validation of the WCP module. "
        "Every link below is a crawlable endpoint mapped to a pipeline step.</p>\n"
        f"{body}\n"
        "</body></html>"
    )
    return cacheable(Response(html, mimetype="text/html"))


@app.route("/health")
def health() -> Response:
    return Response("ok", mimetype="text/plain")


# =========================================================================== #
# STEP 1b — CACHE ORACLE.  Each endpoint emits ONE kind of cache signal so the
# oracle's per-header detection branches are all exercised. (nginx ALSO adds
# X-Cache-Status; these backend headers prove the header-class detection.)
# =========================================================================== #
@page("/oracle/cache-control", "1b · Cache oracle", "Cache-Control: public, max-age -> cache-eligible")
def o_cache_control() -> Response:
    return cacheable(Response("<p>cache-control public</p>", mimetype="text/html"), 120)


@page("/oracle/age", "1b · Cache oracle", "Age header present -> served from cache")
def o_age() -> Response:
    r = cacheable(Response("<p>age</p>", mimetype="text/html"))
    r.headers["Age"] = "137"
    return r


@page("/oracle/cf-cache-status", "1b · Cache oracle", "CF-Cache-Status: HIT (Cloudflare-style)")
def o_cf() -> Response:
    r = cacheable(Response("<p>cf</p>", mimetype="text/html"))
    r.headers["CF-Cache-Status"] = "HIT"
    return r


@page("/oracle/x-cache", "1b · Cache oracle", "X-Cache: HIT status token")
def o_xcache() -> Response:
    r = cacheable(Response("<p>x-cache</p>", mimetype="text/html"))
    r.headers["X-Cache"] = "HIT"
    return r


@page("/oracle/via", "1b · Cache oracle", "Via header -> cache/CDN layer present")
def o_via() -> Response:
    r = cacheable(Response("<p>via</p>", mimetype="text/html"))
    r.headers["Via"] = "1.1 varnish (Varnish/6.0)"
    return r


@page("/oracle/vary", "1b · Cache oracle", "Vary: X-Forwarded-Host -> keyed-header surfaced")
def o_vary() -> Response:
    r = cacheable(Response("<p>vary</p>", mimetype="text/html"))
    r.headers["Vary"] = "X-Forwarded-Host"
    return r


@page("/oracle/x-served-by", "1b · Cache oracle", "X-Served-By / X-Cache-Hits (Fastly-style)")
def o_fastly() -> Response:
    r = cacheable(Response("<p>fastly</p>", mimetype="text/html"))
    r.headers["X-Served-By"] = "cache-fra-eddf8230064-FRA"
    r.headers["X-Cache-Hits"] = "2"
    return r


@page("/oracle/x-varnish", "1b · Cache oracle", "X-Varnish: two numeric ids -> served from cache")
def o_varnish() -> Response:
    r = cacheable(Response("<p>varnish</p>", mimetype="text/html"))
    r.headers["X-Varnish"] = "1001234 1009876"   # two ids = a cache HIT
    return r


@page("/oracle/squid", "1b · Cache oracle", "X-Cache-Lookup (Squid) status token")
def o_squid() -> Response:
    r = cacheable(Response("<p>squid</p>", mimetype="text/html"))
    r.headers["X-Cache-Lookup"] = "HIT from proxy.guinea.local:3128"
    return r


@page("/oracle/imperva", "1b · Cache oracle", "X-Iinfo (Imperva/Incapsula) presence")
def o_imperva() -> Response:
    r = cacheable(Response("<p>imperva</p>", mimetype="text/html"))
    r.headers["X-Iinfo"] = "9-12345678-12345679 NNNN CT(0 0 0) RT(0 0) q(0 0 0 0) r(1 1) U5"
    return r


@page("/oracle/surrogate", "1b · Cache oracle", "Surrogate-Control (Fastly/Akamai) presence")
def o_surrogate() -> Response:
    r = Response("<p>surrogate</p>", mimetype="text/html")
    r.headers["Surrogate-Control"] = "max-age=3600"
    return cacheable(r)


@page("/oracle/cdn-cache-control", "1b · Cache oracle", "CDN-Cache-Control standardized directive")
def o_cdncc() -> Response:
    r = Response("<p>cdn-cc</p>", mimetype="text/html")
    r.headers["CDN-Cache-Control"] = "public, max-age=600"
    return cacheable(r)


@page("/oracle/warning", "1b · Cache oracle", "Warning header (stale-from-cache)")
def o_warning() -> Response:
    r = cacheable(Response("<p>warning</p>", mimetype="text/html"))
    r.headers["Warning"] = '110 - "Response is Stale"'
    return r


@page("/oracle/x-cdn", "1b · Cache oracle", "X-CDN presence header")
def o_xcdn() -> Response:
    r = cacheable(Response("<p>x-cdn</p>", mimetype="text/html"))
    r.headers["X-CDN"] = "Incapsula"
    return r


@page("/oracle/drupal", "1b · Cache oracle", "X-Drupal-Cache status token")
def o_drupal() -> Response:
    r = cacheable(Response("<p>drupal</p>", mimetype="text/html"))
    r.headers["X-Drupal-Cache"] = "HIT"
    return r


@page("/oracle/proxy-cache", "1b · Cache oracle", "X-Proxy-Cache status token")
def o_proxycache() -> Response:
    r = cacheable(Response("<p>proxy-cache</p>", mimetype="text/html"))
    r.headers["X-Proxy-Cache"] = "HIT"
    return r


@page("/oracle/no-store", "1b · Cache oracle (NEGATIVE)", "Cache-Control: no-store -> NOT cacheable, must be skipped")
def o_no_store() -> Response:
    r = Response("<p>no-store</p>", mimetype="text/html")
    r.headers["Cache-Control"] = "no-store, private"
    return r


@page("/oracle/cf-dynamic", "1b · Cache oracle (NEGATIVE)", "CF-Cache-Status: DYNAMIC + private -> NOT cacheable")
def o_cf_dynamic() -> Response:
    r = Response("<p>dynamic</p>", mimetype="text/html")
    r.headers["CF-Cache-Status"] = "DYNAMIC"
    r.headers["Cache-Control"] = "private, no-cache"
    return r


# Silent cache: a cache that emits NO cache-status headers but replays a stored
# response verbatim, INCLUDING its original Date. Only the behavioural (frozen-Date)
# oracle can catch it. Reverse proxies like nginx rewrite Date on every response, so
# this must be served by the backend DIRECTLY (the :9091 direct port, see README) —
# the backend keeps a tiny in-process store and replays a frozen Date + identical
# body, which is exactly what oracle.py's _behavioral_probe looks for.
_SILENT_STORE: dict[str, tuple[str, str]] = {}


@page("/silent/page", "1b · Cache oracle (behavioural)", "Silent cache (frozen Date); test via the direct :9091 port")
def o_silent() -> Response:
    key = request.full_path
    if key not in _SILENT_STORE:
        _SILENT_STORE[key] = (
            "<html><body>silently cached &mdash; stable body</body></html>",
            formatdate(time.time(), usegmt=True),
        )
    body, frozen_date = _SILENT_STORE[key]
    r = Response(body, mimetype="text/html")
    r.headers["Date"] = frozen_date  # replayed verbatim -> frozen across requests
    r.headers["X-Origin-Cache"] = "replay"  # not a recognised cache token; stays "silent"
    return r


# =========================================================================== #
# STEP 4 (reflected) — REFLECTED POISONING.  The injected header value (the
# module's benign canary, e.g. <token>.redamon-poc.invalid) is echoed into the
# response.  Cacheable -> the poisoned response is stored for the next visitor.
# =========================================================================== #
@page("/poison/xfh-redirect", "4 · Reflected -> open_redirect", "X-Forwarded-Host reflected into Location (302)")
def p_xfh_redirect() -> Response:
    xfh = request.headers.get("X-Forwarded-Host", "guinea.local")
    r = make_response("", 302)
    r.headers["Location"] = f"https://{xfh}/welcome"
    return cacheable(r)


@page("/poison/xfh-script", "4 · Reflected -> stored_xss", "X-Forwarded-Host reflected into <script src>")
def p_xfh_script() -> Response:
    xfh = request.headers.get("X-Forwarded-Host", "cdn.guinea.local")
    body = f"<html><head><script src=\"https://{xfh}/static/app.js\"></script></head><body>home</body></html>"
    return cacheable(Response(body, mimetype="text/html"))


@page("/poison/x-host-link", "4 · Reflected -> reflected", "X-Host reflected into <link href>")
def p_xhost() -> Response:
    xh = request.headers.get("X-Host", "assets.guinea.local")
    body = f"<html><head><link rel=stylesheet href=\"https://{xh}/style.css\"></head><body>page</body></html>"
    return cacheable(Response(body, mimetype="text/html"))


@page("/poison/x-forwarded-server", "4 · Reflected", "X-Forwarded-Server reflected into body")
def p_xfserver() -> Response:
    v = request.headers.get("X-Forwarded-Server", "origin.guinea.local")
    return cacheable(Response(f"<html><body>served by: {v}</body></html>", mimetype="text/html"))


@page("/poison/x-original-url", "4 · Reflected", "X-Original-URL reflected into body")
def p_xou() -> Response:
    v = request.headers.get("X-Original-URL", "/dashboard")
    return cacheable(Response(f"<html><body>canonical path: {v}</body></html>", mimetype="text/html"))


@page("/poison/x-rewrite-url", "4 · Reflected", "X-Rewrite-URL reflected into body")
def p_xru() -> Response:
    v = request.headers.get("X-Rewrite-URL", "/app")
    return cacheable(Response(f"<html><body>rewrite target: {v}</body></html>", mimetype="text/html"))


# =========================================================================== #
# STEP 4 (differential) — NON-REFLECTIVE POISONING.  No marker is echoed; the
# poison changes response BEHAVIOUR (status / Location / body).  Catches the
# class the reflection-only confirmer is blind to.
# =========================================================================== #
@page("/diff/proto-redirect", "4 · Differential -> response_change", "X-Forwarded-Proto=https flips to a 301 redirect (Location diff)")
def d_proto() -> Response:
    if (request.headers.get("X-Forwarded-Proto") or "").lower() == "https":
        r = make_response("", 301)
        r.headers["Location"] = "https://secure.guinea.local/account"
        return cacheable(r)
    return cacheable(Response("<html><body>account (plain)</body></html>", mimetype="text/html"))


@page("/diff/status-dos", "4 · Differential -> dos (CPDoS)", "Any X-Forwarded-Host makes the page 403 (status diff, cached for all)")
def d_status() -> Response:
    if first_host_header():
        return cacheable(make_response("<h1>403 Forbidden</h1>", 403))
    return cacheable(Response("<html><body>public article</body></html>", mimetype="text/html"))


@page("/diff/body-banner", "4 · Differential -> response_change", "X-Forwarded-Host swaps in a different body (no echoed marker)")
def d_body() -> Response:
    if first_host_header():
        return cacheable(Response("<html><body>SYSTEM UNDER MAINTENANCE</body></html>", mimetype="text/html"))
    return cacheable(Response("<html><body>live shop content</body></html>", mimetype="text/html"))


# =========================================================================== #
# STEP 3 (framework packs) — fingerprint headers make the Next.js / Nuxt / Remix
# packs plausible, and each reacts to its framework-specific vector.
# =========================================================================== #
@page("/fw/nextjs", "3 · Framework pack (Next.js)", "x-invoke-status forces an error render (CPDoS); X-Powered-By: Next.js")
def fw_next() -> Response:
    invoke = request.headers.get("x-invoke-status")
    if invoke:
        # Next.js renders /_error for this header -> a poisoned error page gets cached
        # (CPDoS). React to the header's PRESENCE: the WCP module sends a benign token
        # value (payload_kind "value"), not a numeric code, so don't require a digit.
        code = int(invoke) if invoke.isdigit() and 400 <= int(invoke) <= 599 else 503
        r = cacheable(make_response(f"<h1>Application error ({code})</h1>", code))
    else:
        r = cacheable(Response(
            "<html><head><meta name=\"generator\" content=\"Next.js\">"
            "</head><body id=\"__next\">home</body>"
            "<script id=\"__NEXT_DATA__\" type=\"application/json\">{\"props\":{}}</script></html>",
            mimetype="text/html"))
    r.headers["X-Powered-By"] = "Next.js"
    return r


@page("/fw/nuxt", "3 · Framework pack (Nuxt)", "Nuxt fingerprint; /_payload.json path confusion")
def fw_nuxt() -> Response:
    r = cacheable(Response(
        "<html><body><div id=\"__nuxt\"></div>"
        "<script>window.__NUXT__={}</script></body></html>", mimetype="text/html"))
    r.headers["X-Powered-By"] = "Nuxt"
    return r


@page("/fw/remix", "3 · Framework pack (Remix)", "Remix fingerprint; _data request mode")
def fw_remix() -> Response:
    # Reflect the _data query param into the body (Remix data-request style).
    data = request.args.get("_data", "")
    extra = f"<!-- _data={data} -->" if data else ""
    r = cacheable(Response(
        f"<html><body><div id=\"remix-app\">dashboard</div>{extra}"
        "<script>window.__remixContext={}</script></body></html>", mimetype="text/html"))
    r.headers["X-Powered-By"] = "Remix"
    return r


# =========================================================================== #
# EXTENDED VECTOR-FAMILY COVERAGE — port / client-IP / host-override / Forwarded /
# stored-XSS context / parameter cloaking.
# =========================================================================== #
@page("/poison/port", "4 · Differential -> response_change", "X-Forwarded-Port reflected into a redirect host:port (Location diff)")
def p_port() -> Response:
    port = request.headers.get("X-Forwarded-Port", "80")
    r = make_response("", 302)
    r.headers["Location"] = f"https://shop.guinea.local:{port}/account"
    return cacheable(r)


@page("/poison/client-ip", "4 · Differential -> response_change", "X-Forwarded-For / X-Real-IP reflected into body (non-canary value)")
def p_clientip() -> Response:
    ip = request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP") \
        or request.headers.get("X-Client-IP") or "10.0.0.1"
    return cacheable(Response(f"<html><body>access granted for ip: {ip}</body></html>", mimetype="text/html"))


@page("/poison/x-host-override", "4 · Reflected -> open_redirect", "X-Host-Override reflected into Location")
def p_hostoverride() -> Response:
    h = request.headers.get("X-Host-Override", "shop.guinea.local")
    r = make_response("", 302)
    r.headers["Location"] = f"https://{h}/dashboard"
    return cacheable(r)


@page("/poison/forwarded", "4 · Reflected -> open_redirect", "RFC 7239 Forwarded header host= reflected into Location")
def p_forwarded() -> Response:
    fwd = request.headers.get("Forwarded", "")
    host = "shop.guinea.local"
    for part in fwd.split(";"):
        if part.strip().lower().startswith("host="):
            host = part.split("=", 1)[1].strip().strip('"') or host
    r = make_response("", 302)
    r.headers["Location"] = f"https://{host}/home"
    return cacheable(r)


@page("/poison/xss-inline", "4 · Reflected -> reflected_script", "X-Forwarded-Host reflected into an INLINE <script> (executable context)")
def p_xss_inline() -> Response:
    xfh = request.headers.get("X-Forwarded-Host", "cdn.guinea.local")
    body = (f"<html><head><script>var apiBase=\"https://{xfh}/api\";fetch(apiBase+\"/beacon\");"
            "</script></head><body>dashboard</body></html>")
    return cacheable(Response(body, mimetype="text/html"))


@page("/poison/param-cloak", "4 · Param cloaking -> reflected", "utm_source reflected into body; the cache strips utm_source from the key (unkeyed param)")
def p_param_cloak() -> Response:
    v = request.args.get("utm_source", "direct")
    return cacheable(Response(f"<html><body>campaign source: {v}</body></html>", mimetype="text/html"))


@page("/poison/fat-get", "8 · Fat GET -> reflected", "reads a `q` param from the GET request BODY and reflects it; the cache keys on the URL only, so the body param is unkeyed")
def p_fat_get() -> Response:
    # A fat-GET-vulnerable origin reads request-body params even on GET, and reads them
    # PREFERENTIALLY over the query (the misconfiguration this class exploits: the app
    # trusts the body, the cache keys only on the URL). Werkzeug does not populate
    # request.form for GET, so parse the body by hand. Body `q` wins; else query `q`.
    # The nginx cache key is URL-only, so the body `q` is UNKEYED -> a poisoned body is
    # cached under the URL and served to body-less victims (class 8, fat-GET cloaking).
    from urllib.parse import parse_qs
    body_vals = parse_qs(request.get_data(as_text=True) or "").get("q")
    q = body_vals[0] if body_vals else request.args.get("q", "none")
    return cacheable(Response(f"<html><body>results for: {q}</body></html>", mimetype="text/html"))


def _account_view(**_kw) -> Response:
    # Web cache deception (class 10): returns SENSITIVE content when a session cookie is
    # present, generic content otherwise. The path-confusion route below serves this same
    # view for /account/<anything>.css, so a cache that stores by extension (URL-keyed,
    # no Cookie in the key) caches the authenticated body and serves it to anon victims.
    if request.cookies.get("session"):
        body = "SENSITIVE account for user: alice (balance 1000)"
    else:
        body = "public: please log in"
    return cacheable(Response(f"<html><body>{body}</body></html>", mimetype="text/html"))


page("/account", "10 · Deception -> sensitive",
     "sensitive when a session cookie is present; /account/x.css path-confuses to it")(_account_view)
# Path confusion: the origin ignores a trailing static-looking segment and serves the
# account page, so /account/<marker>.css returns the sensitive body (a distinct endpoint).
app.add_url_rule("/account/<path:_deco>", endpoint="account_deco",
                 view_func=_account_view, methods=["GET"])


def _menu_view(**_kw) -> Response:
    # Reads a ;matrix path-parameter (;utm_source=) out of the raw path and reflects it.
    # The nginx /normalize/ cache key strips ;params, so a poisoned ;utm_source= value
    # is cached under the clean /normalize/menu key and served to victims (class 9,
    # cache-key normalization abuse).
    import re
    m = re.search(r";utm_source=([^;/?]*)", request.path)
    src = m.group(1) if m else "direct"
    return cacheable(Response(f"<html><body>menu source: {src}</body></html>", mimetype="text/html"))


page("/normalize/menu", "9 · Normalization -> reflected",
     "reflects a ;utm_source matrix path-param; the /normalize/ cache key strips ;params")(_menu_view)
# Werkzeug routes /normalize/menu;utm_source=x as a distinct literal path, so add a
# catch rule (unique endpoint) that funnels the matrix variant to the same view.
app.add_url_rule("/normalize/<path:_matrix>", endpoint="normalize_matrix",
                 view_func=_menu_view, methods=["GET"])


# =========================================================================== #
# NEGATIVE CONTROLS — must be REJECTED by scoring (prove low false-positive rate)
# =========================================================================== #
@page("/safe/keyed-xfh", "Negative · keyed header", "Reflects X-Forwarded-Host BUT nginx KEYS on it -> not poisonable")
def s_keyed() -> Response:
    # Reflection is real, but the nginx /safe/keyed-xfh location adds the header to
    # the cache key, so a poisoned entry is never served to a header-less victim.
    xfh = request.headers.get("X-Forwarded-Host", "safe.local")
    return cacheable(Response(f"<html><body>host: {xfh}</body></html>", mimetype="text/html"))


@page("/safe/no-reflect", "Negative · no reflection", "Cacheable but ignores every header -> nothing to poison")
def s_noreflect() -> Response:
    return cacheable(Response("<html><body>static, header-independent</body></html>", mimetype="text/html"))


@page("/safe/dynamic", "Negative · dynamic body", "Body changes every request -> FP guard must suppress differential")
def s_dynamic() -> Response:
    # A per-request token (no header involved) -> the body legitimately flaps, so the
    # baseline is unstable and the differential detector must NOT fire.
    import os
    nonce = os.urandom(4).hex()
    return cacheable(Response(f"<html><body>request id: {nonce}</body></html>", mimetype="text/html"))


@page("/safe/reflect-no-store", "Negative · reflected but uncacheable", "Reflects X-Forwarded-Host but no-store -> never persists")
def s_reflect_nostore() -> Response:
    xfh = request.headers.get("X-Forwarded-Host", "safe.local")
    r = Response(f"<html><body>echo: {xfh}</body></html>", mimetype="text/html")
    r.headers["Cache-Control"] = "no-store"
    return r


# =========================================================================== #
# FALSE-POSITIVE TRAPS — none of these is poisonable, and each one fooled the
# native confirmer before its control read / reproduction / explicit-MISS rules:
# a same-slot "clean" read is a cache HIT of whatever the poison MISS stored, so
# any page that changes for reasons of its own looked poisoned. All must yield
# NO finding.
# =========================================================================== #
_RENDERS: dict[str, int] = {}
_WAF_BLOCK_UNTIL: dict[str, float] = {}


def _render_count(path: str) -> int:
    _RENDERS[path] = _RENDERS.get(path, 0) + 1
    return _RENDERS[path]


@page("/safe/drift", "Trap · page drift", "Archive page embedding a rotating token (a WordPress nonce/timestamp): the body changes between the baseline and the poison on its own")
def s_drift() -> Response:
    # 50 ms buckets: at LAN latency a whole URL takes well under a second, so a
    # per-second token (what node 217734's page carried, seen across the internet)
    # would never change mid-scan here.
    return cacheable(Response(
        f"<html><body>January 2021 archive<script>var wpNonce='{int(time.time() * 20)}';</script></body></html>",
        mimetype="text/html"))


@page("/safe/ab-variant", "Trap · A/B bucket", "Each origin render picks variant A or B at random (cookie-less A/B test)")
def s_ab_variant() -> Response:
    import random
    return cacheable(Response(
        f"<html><body>hero banner: variant {random.choice('AB')}</body></html>", mimetype="text/html"))


@page("/safe/rare-banner", "Trap · rare banner", "A promo banner shown on ~10% of origin renders")
def s_rare_banner() -> Response:
    import random
    promo = "<div class=promo>SUMMER SALE</div>" if random.random() < 0.10 else ""
    return cacheable(Response(f"<html><body>catalog{promo}</body></html>", mimetype="text/html"))


@page("/safe/utm-cookie", "Trap · origin state", "Stores utm_source in a cookie and renders it from the cookie on later visits; a cookie-carrying client sees its own canary come back with no cache involved")
def s_utm_cookie() -> Response:
    q = request.args.get("utm_source")
    src = q or request.cookies.get("utm_source") or "direct"
    r = cacheable(Response(
        f'<html><body><form><input type="hidden" name="utm_source" value="{src}"></form></body></html>',
        mimetype="text/html"))
    if q:
        r.set_cookie("utm_source", q)  # nginx never caches a response carrying Set-Cookie
    return r


@page("/safe/flaky", "Trap · flaky origin", "Every 7th origin render is a 503 that the cache keeps for 60s; a poison request that happens to catch it looks like CPDoS")
def s_flaky() -> Response:
    if _render_count("/safe/flaky") % 7 == 0:
        return cacheable(make_response("<h1>503 upstream timeout</h1>", 503))
    return cacheable(Response("<html><body>status page</body></html>", mimetype="text/html"))


@page("/safe/waf", "Trap · WAF block", "A spoofed X-Forwarded-For gets the client blocked for 8s with an UNCACHED 403, so every read after the poison fails the same way")
def s_waf() -> Response:
    now = time.time()
    if request.headers.get("X-Forwarded-For"):
        _WAF_BLOCK_UNTIL["/safe/waf"] = now + 8
    if now < _WAF_BLOCK_UNTIL.get("/safe/waf", 0):
        r = make_response("<h1>403 Request blocked</h1>", 403)
        r.headers["Cache-Control"] = "no-store"
        return r
    return cacheable(Response("<html><body>protected page</body></html>", mimetype="text/html"))


@page("/safe/query-ignored", "Trap · unisolatable cache", "Reflects X-Forwarded-Host (genuinely poisonable) but the nginx key IGNORES the query string, so a cache-buster cannot isolate a test: the module must skip it and never poison")
def s_query_ignored() -> Response:
    xfh = request.headers.get("X-Forwarded-Host", "cdn.guinea.local")
    return cacheable(Response(
        f"<html><head><link rel=stylesheet href=\"https://{xfh}/site.css\"></head><body>shop</body></html>",
        mimetype="text/html"))


if __name__ == "__main__":
    # waitress respects an app-provided Date header (only adds one when absent), so the
    # /silent/ endpoint can replay a single frozen Date. The Flask dev server adds its
    # own current-time Date, which would defeat the frozen-Date oracle test.
    from waitress import serve
    # clear_untrusted_proxy_headers=False: KEEP the X-Forwarded-* headers. Waitress
    # strips them by default (a hardening feature) — but this guinea pig is supposed to
    # trust them so the WCP vectors actually reach the app.
    # No ident: waitress derives a "Via: <ident>" header from it, which would make the
    # oracle see every response as a cache layer. We set Server ourselves in after_request.
    serve(app, host="0.0.0.0", port=5000, threads=8,
          clear_untrusted_proxy_headers=False)

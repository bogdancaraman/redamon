"""Deliberately "serialized-object leaky" guinea-pig target.

End-to-end validation harness for RedAmon's recon ``serialized_scan`` module and
the agent ``deserialization`` built-in skill. Every endpoint emits ONE family's
serialization signature on the RESPONSE side (Content-Type, Set-Cookie, or a
custom response header) because that is the slice the passive recon scanner can
see in memory (http_probe response headers + resource_enum params). The blobs
are inert detection fixtures (see payloads.py) -- no gadget. TWO endpoints are
real sinks on purpose:
  * /python/pickle4 pickle.loads its `session` request cookie and reports a
    failure (_pickle_sink_response): the out-of-band and error channels confirm it;
  * /account/prefs pickle.loads its `prefs` request cookie and answers the same
    page either way (_blind_pickle_response): blind, so only the out-of-band and
    timing channels can confirm it.

Stdlib only; runs on port 80. Real code execution through those sinks, so never
expose it to an untrusted network (the compose file binds the host alias to
loopback).
"""

from __future__ import annotations

import base64
import html
import os
import pickle  # noqa: S403 - deliberate insecure sink for the agent-confirmation test
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import payloads as P

PORT = int(os.environ.get("PORT", "80"))

# Group emit directives by path (a path may emit several, e.g. /java/native
# sets both a serialized Content-Type and a serialized Set-Cookie).
_BY_PATH: dict[str, list] = defaultdict(list)
for path, title, kind, (name, value), expected, transport in P.ENDPOINTS:
    _BY_PATH[path].append((title, kind, name, value, expected))

# Param-transport surface: crawlable links whose query parameters carry a
# serialized value, and a parameter NAMED like a .NET sink. resource_enum feeds
# these to the scanner's param path (deser_transport="param").
_PARAM_LINKS = [
    ("/api/load?data=" + P.URL_B64_JAVA, "GET /api/load?data= (Java base64 in a query param)"),
    ("/api/state?__VIEWSTATE=" + P.VIEWSTATE.split("=", 1)[1], "GET /api/state?__VIEWSTATE= (ASP.NET viewstate param)"),
]

# The blind sink's own cookie: a real protocol-4 pickle of harmless preferences.
_PREFS_COOKIE = base64.b64encode(pickle.dumps({"theme": "dark", "lang": "en"}, protocol=4)).decode()


def _landing() -> bytes:
    rows = []
    for path in _BY_PATH:
        titles = ", ".join(sorted({t for t, *_ in _BY_PATH[path]}))
        rows.append(f'<li><a href="{path}">{path}</a> &mdash; {titles}</li>')
    for href, label in _PARAM_LINKS:
        rows.append(f'<li><a href="{href}">{label}</a></li>')
    rows.append('<li><a href="/forms/aspnet">/forms/aspnet</a> &mdash; hidden __VIEWSTATE form</li>')
    rows.append('<li><a href="/account/prefs">/account/prefs</a> &mdash; user preferences</li>')
    items = "\n".join(rows)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Serialized Object Showroom</title></head>
<body>
<h1>Serialized Object Showroom (guinea pig)</h1>
<p>Each link exposes one serialized-object family signature on the response side
for RedAmon recon to flag.</p>
<ul>
{items}
</ul>
</body></html>""".encode("utf-8")


_ASPNET_FORM = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Legacy ASP.NET page</title></head>
<body>
<form method="post" action="/forms/aspnet">
<input type="hidden" name="__VIEWSTATE" value="{P.VIEWSTATE.split('=', 1)[1]}">
<input type="hidden" name="__EVENTVALIDATION" value="/wEWAgKM54rGBgKfy5">
<input type="hidden" name="data" value="{html.escape(P.JACKSON_JSON, quote=True)}">
<input type="submit" value="go">
</form>
</body></html>""".encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "SerializedShowroom/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quieter logs
        pass

    def _send(self, body: bytes, directives: list, content_type_override: str | None = None):
        self.send_response(200)
        ct = content_type_override or "text/html; charset=utf-8"
        # Custom headers + Set-Cookie + optional serialized Content-Type.
        emitted_ct = None
        for title, kind, name, value, expected in directives:
            if kind == "content_type":
                emitted_ct = value
            elif kind == "cookie":
                self.send_header("Set-Cookie", f"{name}={value}; Path=/; HttpOnly")
            elif kind == "header":
                self.send_header(name, value)
        self.send_header("Content-Type", emitted_ct or ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _pickle_sink_response(self):
        """INTENTIONALLY VULNERABLE real sink for the agent-confirmation test.

        /python/pickle4 deserializes its ``session`` request cookie with
        pickle.loads. A cookieless request (recon's httpx probe) takes the normal
        path and still emits the detection Set-Cookie, so recon keeps flagging the
        candidate. A request WITH a session cookie is pickle.loads'd:
          * the agent's non-destructive DNS oracle (__reduce__ -> gethostbyname of
            the OAST domain) actually fires -> interactsh callback = confirmation;
          * a corrupt/flipped blob raises -> 500 with the exception name, which is
            the B3 error-differential channel.
        Guinea-pig lab on an isolated Docker network only.
        """
        sess = self._cookie("session")
        if sess:
            try:
                pickle.loads(base64.b64decode(sess, validate=False))  # noqa: S301
            except Exception as e:  # noqa: BLE001 - error differential is the point
                body = f"<html><body>pickle.loads error: {type(e).__name__}</body></html>".encode()
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("X-Deser-Error", type(e).__name__)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
                return
        return self._send(
            b"<html><body><h2>/python/pickle4</h2><p>serialized fixture</p></body></html>",
            _BY_PATH["/python/pickle4"],
        )

    def _cookie(self, name: str) -> str | None:
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name) + 1:]
        return None

    def _blind_pickle_response(self):
        """INTENTIONALLY VULNERABLE blind sink for the timing-channel test.

        /account/prefs pickle.loads its ``prefs`` request cookie but answers the
        same page whether loading succeeds or fails, so the error channel shows
        nothing: only a timing or out-of-band oracle can prove it deserializes.
        """
        prefs = self._cookie("prefs")
        if prefs:
            try:
                pickle.loads(base64.b64decode(prefs, validate=False))  # noqa: S301
            except Exception:  # noqa: BLE001, S110 - blind on purpose
                pass
        body = b"<html><body><h2>Preferences</h2><p>Your preferences are saved.</p></body></html>"
        self.send_response(200)
        self.send_header("Set-Cookie", f"prefs={_PREFS_COOKIE}; Path=/; HttpOnly")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/python/pickle4":
            return self._pickle_sink_response()
        if path == "/account/prefs":
            return self._blind_pickle_response()
        if path in ("/", "/index.html"):
            return self._send(_landing(), [])
        if path == "/forms/aspnet":
            return self._send(_ASPNET_FORM, [])
        if path in _BY_PATH:
            return self._send(
                f"<html><body><h2>{path}</h2><p>serialized fixture</p></body></html>".encode(),
                _BY_PATH[path],
            )
        if path in ("/api/load", "/api/state"):
            # Param-transport endpoints: the signature rides the query string.
            return self._send(b"<html><body>ok</body></html>", [])
        # 404 for unknown paths (realistic surface).
        body = b"<html><body><h1>404</h1></body></html>"
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_HEAD = do_GET
    do_POST = do_GET


if __name__ == "__main__":
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[serialized-target] listening on :{PORT}; {len(_BY_PATH)} endpoints, "
          f"{sum(len(v) for v in _BY_PATH.values())} emit directives")
    httpd.serve_forever()

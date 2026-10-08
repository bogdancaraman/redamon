"""False-positive regression guinea pig: one server, the behaviour picked by ROLE.

Each role replicates a shape a field report muted by the hundred, next to a
real finding that must survive. Stdlib only. See README.md for the case table.

    ROLE=fastly     shared edge: unknown Host -> 500 page echoing the name twice,
                    a different cache node per request; hides admin + wiki apps
    ROLE=cloudflare TLS edge: block page with a fresh Ray ID unless the SNI names
                    the one hidden app
    ROLE=redirect   every name -> 301 to https://<name>/
    ROLE=akamai     deny page with an entity-encoded reference that changes per request
    ROLE=ratelimit  a third of the names get 429; admin answers once, then 429
    ROLE=cache      a tiny shared cache: an A/B page and a real unkeyed-header poisoning
    ROLE=spa        single-page app + JS bundles + source maps (catch-all HTML shell)
    ROLE=vendor     a third-party script host
    ROLE=shodan     canned Shodan host API + InternetDB answers for the lab IPs
"""

import base64
import hashlib
import itertools
import json
import os
import random
import ssl
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = os.environ.get("ROLE", "spa")
PORTS = [int(p) for p in os.environ.get("PORTS", "80").split(",") if p]
TLS_PORTS = {int(p) for p in os.environ.get("TLS_PORTS", "").split(",") if p}
APEX = "fplab.test"
STATIC = "/app/static"
_counter = itertools.count(1)
_lock = threading.Lock()


class Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fplab"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Never log a query string: the Shodan stub may receive an API key.
        print(f"[{ROLE}] {self.command} {self.path.split('?', 1)[0]} host={self.headers.get('Host', '')}", flush=True)

    def send(self, status, body=b"", ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def host(self):
        return (self.headers.get("Host") or "").split(":")[0].strip().lower()

    def is_bare_ip(self):
        h = self.host()
        return not h or h.replace(".", "").isdigit()

    def do_HEAD(self):
        self.do_GET()


# --------------------------------------------------------------------------- vhost edges
class Fastly(Base):
    def do_GET(self):
        host = self.host()
        if self.is_bare_ip():
            return self.send(421, "<h1>Misdirected Request</h1>")
        if host == f"admin.{APEX}":
            return self.send(200, '{"service":"admin-api","version":"3.2.1"}', "application/json")
        if host == f"wiki.{APEX}":
            n = next(_counter)
            return self.send(200, f"<html><head><title>Internal Wiki</title></head><body>Main page. "
                                  f"Rendered in 0.0{n % 9 + 1}s, {n} views</body></html>")
        node = f"cache-fra-etou82{random.randint(10000, 99999)}-FRA"
        return self.send(500, f"<html><body><h1>Fastly error: unknown domain: {host}</h1>"
                              f"<p>Please check that this domain has been added to a service: {host}</p>"
                              f"<p>Details: {node} {int(time.time())}</p></body></html>")


class Cloudflare(Base):
    def do_GET(self):
        sni = getattr(self.request, "_sni", "") or ""
        host = self.host()
        if sni == f"admin.{APEX}" and host == sni:
            return self.send(200, '{"service":"admin-console","build":"7f1c"}', "application/json")
        ray = uuid.uuid4().hex[:16]
        return self.send(403, f"<html><head><title>Attention Required! | Cloudflare</title></head><body>"
                              f"<h1>Sorry, you have been blocked</h1><p>You are unable to access {host or 'this site'}</p>"
                              f"<p>Cloudflare Ray ID: <strong>{ray}</strong></p>"
                              f"<p>{time.strftime('%Y-%m-%d %H:%M:%S')} UTC</p></body></html>",
                         headers={"cf-ray": f"{ray}-FRA", "Server": "cloudflare"})


class Redirect(Base):
    def do_GET(self):
        if self.is_bare_ip():
            return self.send(404, b"", ctype=None)
        return self.send(301, b"", ctype=None, headers={"Location": f"https://{self.host()}/"})


class Akamai(Base):
    def do_GET(self):
        if self.is_bare_ip():
            return self.send(400, "<HTML><HEAD><TITLE>Invalid URL</TITLE></HEAD><BODY>Invalid URL</BODY></HTML>")
        ref = f"{random.randint(16, 99)}&#46;{uuid.uuid4().hex[:8]}&#46;{int(time.time())}&#46;{uuid.uuid4().hex[:8]}"
        return self.send(403, f"<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>"
                              f"You don't have permission to access \"http&#58;&#47;&#47;{self.host()}&#47;\" on this server.<P>"
                              f"Reference&#32;&#35;{ref}<P>https&#58;&#47;&#47;errors&#46;edgesuite&#46;net&#47;{ref}</P>"
                              f"</BODY></HTML>", headers={"Server": "AkamaiGHost"})


_LIMITED = {f"{w}.{APEX}" for w in ("dev", "qa", "ci", "vpn", "sso", "mail", "status")}
_seen_admin = {"n": 0}


class RateLimit(Base):
    def do_GET(self):
        host = self.host()
        if self.is_bare_ip():
            return self.send(404, "<h1>not found</h1>")
        if host == f"admin.{APEX}":
            with _lock:
                _seen_admin["n"] += 1
                first = _seen_admin["n"] == 1
            if first:
                return self.send(200, '{"service":"admin-reports"}', "application/json")
            return self.send(429, "<h1>Too Many Requests</h1>", headers={"Retry-After": "30"})
        if host in _LIMITED:
            return self.send(429, "<h1>Too Many Requests</h1>", headers={"Retry-After": "30"})
        return self.send(404, "<h1>not found</h1>")


# --------------------------------------------------------------------------- cache
_cache = {}
_renders = itertools.count()


class Cache(Base):
    """A shared cache keyed on path + query only, so request headers are unkeyed."""
    TTL = 300

    def do_GET(self):
        key = self.path
        with _lock:
            hit = _cache.get(key)
            if hit and time.time() - hit[0] < self.TTL:
                status, body, ctype = hit[1]
                age = int(time.time() - hit[0])
                return self.send(status, body, ctype, headers={"X-Cache": "HIT", "Age": str(age),
                                                               "Cache-Control": "public, max-age=300"})
        status, body, ctype = self.origin()
        if status == 200:
            with _lock:
                _cache[key] = (time.time(), (status, body, ctype))
        return self.send(status, body, ctype, headers={"X-Cache": "MISS", "Age": "0",
                                                       "Cache-Control": "public, max-age=300"})

    def origin(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            return 200, ('<html><head><title>Shop</title></head><body><a href="/promo">Promo</a> '
                         '<a href="/home">Home</a></body></html>'), "text/html; charset=utf-8"
        if path == "/promo":
            # An A/B bucket picked per origin render: two variants, same size.
            variant = "AB"[next(_renders) % 2]
            return 200, f"<html><body><h1>Spring promo</h1><p>variant {variant}</p></body></html>", "text/html; charset=utf-8"
        if path == "/home":
            # Real poisoning: an unkeyed header reflected into a cached script tag.
            xfh = self.headers.get("X-Forwarded-Host") or "shop.fplab.test"
            return 200, (f'<html><head><script src="https://{xfh}/static/app.js"></script></head>'
                         f'<body>Welcome</body></html>'), "text/html; charset=utf-8"
        return 404, "<h1>not found</h1>", "text/html; charset=utf-8"


# --------------------------------------------------------------------------- JS
def _big_bundle():
    """A one-line minified bundle: the global-object shim first, 400 sourceless
    sinks, then the real hash -> innerHTML bug far down the line."""
    parts = ['!function(){var g=function(){return this}()||Function("return this")();']
    parts += [f"a{i}.innerHTML=r{i}(d);" for i in range(400)]
    parts += ["var o=document.getElementById('out');o.innerHTML=decodeURIComponent(location.hash.slice(1));}();"]
    return "".join(parts)


_MAIN_SRC = None


def _main_js():
    global _MAIN_SRC
    if _MAIN_SRC is None:
        with open(os.path.join(STATIC, "js", "main.src.js")) as f:
            readable = f.read()
        _MAIN_SRC = readable + "\n" + _big_bundle() + "\n//# sourceMappingURL=main.4f2a9c.js.map\n"
    return _MAIN_SRC


def _inline_map():
    m = {"version": 3, "mappings": "AAAA", "sources": ["webpack:///./src/inline-widget.ts"],
         "sourcesContent": ["export const widget = () => 'inline';"]}
    return "data:application/json;base64," + base64.b64encode(json.dumps(m).encode()).decode()


class Spa(Base):
    MAPS = {
        "/static/js/main.4f2a9c.js.map": ({
            "version": 3, "file": "main.js", "mappings": "AAAA;AACA",
            "sources": ["webpack:///./src/App.tsx", "webpack:///./src/api/client.ts",
                        "webpack:///node_modules/react/index.js", "webpack:///webpack/bootstrap"],
            "sourcesContent": ["export const App = () => null;", "export const api = '/api/v1';",
                               "module.exports = {};", "(()=>{})()"],
        }, "application/octet-stream"),
        "/static/js/lib.8e1f.js.map": ({
            "version": 3, "mappings": "AAAA",
            "sources": ["webpack:///node_modules/lodash/lodash.js", "webpack:///webpack/bootstrap"],
        }, "application/json"),
    }

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/static/js/main.4f2a9c.js":
            return self.send(200, _main_js(), "application/javascript")
        if path == "/static/js/inline.5e6f.js":
            return self.send(200, "export const w=1;\n//# sourceMappingURL=" + _inline_map() + "\n", "application/javascript")
        if path in self.MAPS:
            data, ctype = self.MAPS[path]
            return self.send(200, json.dumps(data), ctype)
        if path == "/static/js/private.9c3d.js.map":
            return self.send(403, "<h1>Forbidden</h1>")
        local = os.path.join(STATIC, path[len("/static/"):])
        if path.startswith("/static/") and os.path.isfile(local) and ".." not in path:
            with open(local, "rb") as f:
                return self.send(200, f.read(), "application/javascript" if path.endswith(".js") else "application/octet-stream")
        with open(os.path.join(STATIC, "index.html"), "rb") as f:   # the SPA catch-all
            return self.send(200, f.read(), "text/html; charset=utf-8")


class Vendor(Base):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/loader.js":
            with open(os.path.join(STATIC, "vendor-loader.js"), "rb") as f:
                return self.send(200, f.read(), "application/javascript")
        if path == "/loader.js.map":
            return self.send(200, json.dumps({
                "version": 3, "mappings": "AAAA", "sources": ["webpack:///./src/tracker.ts"],
                "sourcesContent": ["export const track = (e) => e;"]}), "application/json")
        return self.send(404, "<h1>not found</h1>")


# --------------------------------------------------------------------------- Shodan stub
NET = "192.88.94"
SHODAN_HOSTS = {
    f"{NET}.10": {"org": "Example Hosting Ltd", "isp": "Example Hosting Ltd", "tags": [], "ports": [80],
                  "vulns": ["CVE-2021-23017", "CVE-2019-11043"],
                  "data": [{"port": 80, "transport": "tcp", "product": "nginx", "version": "1.18.0",
                            "data": "HTTP/1.1 500\r\nServer: nginx", "_shodan": {"module": "http"},
                            "vulns": {"CVE-2021-23017": {"cvss": 7.7, "verified": False}}}]},
    f"{NET}.11": {"org": "Vercel, Inc", "isp": "Vercel, Inc", "tags": [], "ports": [443],
                  "vulns": ["CVE-2020-11022", "CVE-2020-11023"], "data": []},
    f"{NET}.12": {"org": "Example Edge", "isp": "Example Edge", "tags": ["cdn"], "ports": [80],
                  "vulns": ["CVE-2019-11358"], "data": []},
    f"{NET}.13": {"org": "Example Hosting Ltd", "isp": "Example Hosting Ltd", "tags": [], "ports": [80, 443],
                  "vulns": ["CVE-2014-0160"],
                  "data": [{"port": 80, "transport": "tcp", "product": "OpenSSL", "version": "1.0.1f",
                            "data": "", "_shodan": {"module": "http"},
                            "vulns": {"CVE-2014-0160": {"cvss": 7.5, "verified": False}}},
                           {"port": 443, "transport": "tcp", "product": "OpenSSL", "version": "1.0.1f",
                            "data": "", "_shodan": {"module": "https"},
                            "vulns": {"CVE-2014-0160": {"cvss": 7.5, "verified": True}}}]},
}


class Shodan(Base):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/shodan/host/"):
            ip = path.rsplit("/", 1)[-1]
            host = SHODAN_HOSTS.get(ip)
            if not host:
                return self.send(404, '{"error":"No information available for that IP."}', "application/json")
            return self.send(200, json.dumps({"ip_str": ip, "os": None, "country_name": "Ireland",
                                              "city": "Dublin", **host}), "application/json")
        if path.startswith("/internetdb/"):
            ip = path.rsplit("/", 1)[-1]
            host = SHODAN_HOSTS.get(ip)
            if not host:
                return self.send(404, '{"detail":"No information available"}', "application/json")
            return self.send(200, json.dumps({"ip": ip, "ports": host["ports"], "hostnames": [],
                                              "cpes": [], "tags": host["tags"], "vulns": host["vulns"]}),
                             "application/json")
        if path.startswith("/api-info"):
            return self.send(200, '{"plan":"dev","query_credits":100,"scan_credits":100}', "application/json")
        return self.send(404, '{"error":"not found"}', "application/json")


# --------------------------------------------------------------------------- main
ROLES = {"fastly": Fastly, "cloudflare": Cloudflare, "redirect": Redirect, "akamai": Akamai,
         "ratelimit": RateLimit, "cache": Cache, "spa": Spa, "vendor": Vendor, "shodan": Shodan}


def _tls_context():
    cert, key = "/tmp/cert.pem", "/tmp/key.pem"
    if not os.path.exists(cert):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                        "-out", cert, "-days", "30", "-subj", f"/CN=*.{APEX}"], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    def remember_sni(sock, server_name, _ctx):
        sock._sni = (server_name or "").lower()
    ctx.sni_callback = remember_sni
    return ctx


def main():
    handler = ROLES[ROLE]
    servers = []
    for port in PORTS:
        srv = ThreadingHTTPServer(("0.0.0.0", port), handler)
        if port in TLS_PORTS:
            srv.socket = _tls_context().wrap_socket(srv.socket, server_side=True)
        servers.append(srv)
        print(f"[{ROLE}] listening on {port}{' (tls)' if port in TLS_PORTS else ''}", flush=True)
    for srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()

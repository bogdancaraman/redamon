# Guinea Pigs

Deliberately vulnerable, self-contained Docker targets for **end-to-end validation**
of RedAmon recon/scan modules against realistic, real-world behaviour (not mocks).

Each subdirectory is one module's validation harness with its own `docker-compose.yml`
and a README mapping every endpoint to the exact pipeline step it exercises.

| Harness | Validates | Run |
|---|---|---|
| [`web-cache-poisoning/`](web-cache-poisoning/) | `recon/cache_scan` (WCP module): cache oracle, cache-buster isolation, reflected + differential confirmation, framework packs, scoring, negative controls | `cd web-cache-poisoning && docker compose up -d --build` |
| [`supply_chain_target/`](supply_chain_target/) | Supply-Chain recon (L2): both harvest paths (technologies + source-map mining), scoped/nested/hostile package names, version-preferring dedup, `source_files[:100]` cap, offline OSV verdicts (MAL vs CVE), `Package`/`MalPackageFinding` MERGE + `DEPENDS_ON` anchoring | `cd supply_chain_target && docker compose up -d --build` |
| [`proxy_brain_target/`](proxy_brain_target/) | Agent `proxy_brain` / `redamon.*`: IDOR/BOLA, SQLi (boolean/error/UNION), reflected XSS, JWT weak-secret role-forge (flag), race/limit-overrun, open redirect, CORS, command injection — one endpoint per manual technique, on `pentest-net` as `pbtarget:5000` | `cd proxy_brain_target && docker compose up -d --build` |
| [`auth_target/`](auth_target/) | **Authenticated Session Recording**: real cookie login (hidden CSRF + `Set-Cookie`), a post-login surface unreachable anonymously (proves an authenticated crawl finds what an anonymous one cannot), one endpoint per auth mode (bearer/basic/apikey/header), oversized + `;;`-delimiter cookies, multi `Set-Cookie`, and `/whoami` to prove `X-Redamon-Ctx` never leaks to the target. Several `pentest-net` aliases (`authpig.test`, `app./api./cdn.*`, plus an out-of-scope `outsider.example-evil.test`) so the scope rules are testable for real | `cd auth_target && docker compose up -d --build` |
| [`js_scope_target/`](js_scope_target/) | **JS recon endpoint scope**: in-scope JS endpoints (relative, absolute, an unprobed port, a WebSocket, an uploaded file) become Endpoints owned by their BaseURL; third-party and non-target hosts never do; a partial run on a user URL; pre-existing endpoints are neither deleted nor re-fetched. Two hosts on `192.88.97.0/24`, one of them an out-of-scope outsider that logs every request | `cd js_scope_target && docker compose up -d --build` |
| [`tls_target/`](tls_target/) | **TLS Certificate Grab (tlsx)**: cert capture on non-HTTP ports (IMAPS/LDAPS) where httpx grabs nothing, `Service.tls_service_hint`, `COVERS_HOST` for in-scope SANs, the apex allow-list holding against an out-of-scope SAN the certificate actually carries, and the TLS-hygiene findings (expired / self-signed / hostname-mismatch) | `cd tls_target && docker compose up -d --build` |

| [`vhost_target/`](vhost_target/) | **VHost & SNI Enumeration**: three virtual hosts on one address, reachable only by Host header (L7) or SNI name (L4) and present in no DNS zone. Covers the hidden in-scope panel that must still be reachable in the graph, a co-hosted third-party name that must never join the inventory, unknown hosts that answer the baseline and must not become findings, and the `RESOLVES_TO` edge a routing result must never assert | `cd vhost_target && docker compose up -d --build` |
| [`fix_regression_target/`](fix_regression_target/) | **Recon fix regression**, end to end in IP mode with a negative control beside every positive: the port/service security checks firing per IP and port (SSH, MySQL, Redis no-auth, Kubernetes API), the Kubernetes matcher ignoring a page that only says "kind", `ip_api_exposed` at medium for a protected API, one HttpOnly cookie no longer hiding another, nmap technology linked to its own IP on a shared port, and no DNS finding on the IP-mode root. `validate_e2e.py` asserts the graph over MCP; `run_direct_checks.sh` runs the old and the fixed code side by side | `cd fix_regression_target && docker compose up -d --build` |
| [`jev_target/`](jev_target/) | **TypeSafe Jev hooks**, end to end in IP mode (`192.88.96.0/24`): two PHP/Apache apps (one sorts last, so Jev has a crawl order to change) with many directories, a JS bundle and 404s for unknown paths (page type, FFuf extensions and base paths, Nuclei tags, Hakrawler seed order), a host that answers injection-looking requests with a vendor-less challenge page (the WAF classifier, driven directly: the WAF-bypass check needs a hostname/IP pair), and a "coming soon" placeholder. Takeover needs a CNAME and is not covered here | `cd jev_target && docker compose up -d --build` |

> `supply_chain_target` binds `192.88.99.10` on its own bridge rather than
> `127.0.0.1`: L2's JS fetch is Python and enforces an SSRF guard that rejects
> every non-routable address. See its README for why that prefix.

## Recon harness gotchas

Each of these made a working pipeline look broken:

- **Give a recon target a fixed IP on `redamon-network`.** A project pins its scan
  to the target IP, and an auto-assigned IP changes on every restart: the crawler
  then seeds a dead URL, finds 0 endpoints, and the vuln module has nothing to scan.
  Pick a high host (`.90`+) to stay out of the auto-assign range, as
  [`web-cache-poisoning/docker-compose.yml`](web-cache-poisoning/docker-compose.yml)
  does, and target the IP, not the container name: scan containers run with
  `network_mode="host"` and cannot resolve container DNS. Keep the lab up for the
  whole run.
- **Recreate a caching front end before re-running recon.** katana crawls `/` with
  no cache-buster, so it reads the cached landing page and never sees an endpoint
  added after it was cached. Run `docker compose up -d --force-recreate cache`,
  send one warm request, then scan. A `?cb=` curl hides the problem, so check the
  un-busted `/`.
- **Keep `<` and `>` out of endpoint descriptions** on a landing page that renders
  them unescaped. `/account/<x>.css` emits a stray tag that breaks katana's HTML
  parse and drops that link.
- **Recreate, do not restart, after editing a single bind-mounted file** such as
  `nginx/default.conf`: snap Docker binds a file by inode, so `restart` keeps the
  old one.
- **Start a recon run headless** with `POST /recon/{project_id}/start` on the
  orchestrator (`127.0.0.1:8010`, header `X-Orchestrator-Key` from `.env`). The
  body needs `project_id`, `user_id` and `webapp_api_url`.

> ⚠️ These targets are intentionally vulnerable. Run them only on a local/trusted
> Docker host and never expose their ports to an untrusted network.

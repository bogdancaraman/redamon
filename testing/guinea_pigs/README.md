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

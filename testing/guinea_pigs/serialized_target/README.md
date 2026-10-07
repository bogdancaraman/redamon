# serialized_target

Deliberately "serialized-object leaky" guinea pig for end-to-end validation of
the RedAmon **`recon/serialized_scan`** module and the agent **`deserialization`**
built-in skill.

```bash
docker compose up -d --build
curl -s http://172.25.0.92/            # landing page links every endpoint
curl -sD - -o /dev/null http://172.25.0.92/java/native   # see the serialized Content-Type + Set-Cookie
```

## What it exercises

Recon's `serialized_scan` is **passive and in-memory**: it only sees the slice
the pipeline already holds -- httpx **response headers + Set-Cookie** for the URLs
httpx probed, and resource_enum **params** and crawled **form fields**. Every
endpoint here emits one serialization family signature on the **response side**
(Content-Type, Set-Cookie, or a custom response header), in a form, or in a
crawlable link's query, all of which the scanner matches without deserializing
anything. A default live run probes only the root URL, so a deeper endpoint's
response headers reach the scanner only when that path is probed (`httpxPaths`);
otherwise they are the agent's to find in captured traffic.

All 13 families (`native_java, hessian, jackson_json, fastjson, xmldecoder,
xstream, snakeyaml, php_serialize, phar, python_pickle, dotnet_binaryformatter,
viewstate, ruby_marshal`) plus decode-and-recurse layers (`base64(gzip)`,
`url(base64)`) and a decompression-bomb safety fixture. See
[`expected_results.yaml`](expected_results.yaml) for the per-endpoint matrix and
[`payloads.py`](payloads.py) for how each blob is built.

The blobs are **inert detection fixtures** -- byte prefixes and structural
markers only, no gadget, no class graph. `validate_jev_e2e.py` (below) checks that
a default live recon run flags every family it can see.

**One real sink, on purpose.** `/python/pickle4` runs `pickle.loads` on its
`session` *request* cookie, so the agent's `deserialization` skill has something to
confirm: its non-destructive DNS oracle really fires (interactsh callback), and a
corrupt blob returns `500` with an `X-Deser-Error` header (the error-differential
channel). A cookieless request, such as recon's probe, takes the normal path and
still gets the detection `Set-Cookie`.

## End-to-end case test (with the Jev ranking)

`validate_jev_e2e.py` drives the whole thing through the inbound MCP server, the way
an external agent would. It reads `MCP_SERVER_TOKEN` from the repo `.env` and never
prints it; the token's owner needs a TypeSafe Jev token.

```bash
cd testing/guinea_pigs/serialized_target
python3 validate_jev_e2e.py setup               # project + Jev toggles + start_recon
python3 validate_jev_e2e.py verify <projectId>  # once the recon has finished
```

`setup` checks that `describe_recon_settings` lists `serializedScanJevRank`, creates
an internal IP-mode project on this lab, checks that it stores the flag false and
that `update_recon_settings` switches it on and off with `preflight_scope_check`
following (`serialized_assess`: off, jev, off), then starts the recon. `verify` checks
that every family in `live_in_memory_formats` is a `serialized_scan` candidate in the
graph (the others ride only in a deeper endpoint's response header or `Set-Cookie`,
which the in-memory corpus never holds, so they are reported as a known gap; see
`expected_results.yaml`), that no sink is flagged twice for one format, that the recon
output holds `jev_shadow.serialized_assess` (act rollout, model `jev-1.13.0`,
decisions, no fallback, closed-set answers), that every candidate in the graph carries
Jev's `deser_jev_*` annotation, and that the deserialization skill's own candidate
query returns them most reachable first. It prints Jev's agreement with the
signatures per format without asserting it: Jev's format is a second opinion, not a
test oracle.

## Wiring

Fixed IP `172.25.0.92` on the external `redamon-network` (survives restarts;
scan containers run `--net=host` and cannot resolve container names, so pin the
project to the **IP**, port 80). Host alias `localhost:9092` for manual curl.

> Intentionally vulnerable: `/python/pickle4` is real code execution. Local/trusted
> Docker host only. The compose file binds the `9092` alias to `127.0.0.1`; never
> publish it on another interface.

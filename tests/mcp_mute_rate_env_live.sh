#!/usr/bin/env bash
# =============================================================================
# LIVE check: MCP_RATE_MUTE_PER_MIN reaches the running webapp.
#
# The rate is how many mute and unmute calls one MCP token makes a minute, and
# it is read from the webapp's environment. A value set in .env that compose
# does not pass through is silently inert: the webapp keeps its default of 200.
#
#   1. The running redamon-webapp's value equals what .env configures (both
#      empty when .env leaves it unset, which means the default).
#   2. compose renders a value for the webapp when one is set, so (1) is not
#      passing only because both sides happen to be empty.
#
# (2) does not restart anything. After changing .env, recreate the webapp
# (`docker compose up -d webapp`) before (1) can pass.
#
# Not part of `./redamon.sh test` (the gate matches tests/*_test.sh only). Run:
#     bash tests/mcp_mute_rate_env_live.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VAR=MCP_RATE_MUTE_PER_MIN
CONTAINER=redamon-webapp

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
skip() { echo "  SKIP  $1"; exit 0; }

command -v docker >/dev/null 2>&1 || skip "docker unavailable ($VAR)"
docker info >/dev/null 2>&1        || skip "docker daemon unreachable ($VAR)"
[[ -f "$REPO_ROOT/.env" ]]         || skip "no .env at the repo root ($VAR)"
[[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" == "true" ]] \
    || skip "$CONTAINER is not running ($VAR)"

# The last assignment wins, as compose reads it; quotes are compose syntax.
configured="$(grep -E "^[[:space:]]*${VAR}=" "$REPO_ROOT/.env" | tail -1 | cut -d= -f2- \
    | sed -e 's/[[:space:]]*#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
          -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")"
running="$(docker exec "$CONTAINER" printenv "$VAR" 2>/dev/null || true)"

echo "$VAR reaches the running webapp"
if [[ "$running" == "$configured" ]]; then
    ok "$CONTAINER has $VAR='${running}' as .env configures (empty = the default of 200)"
else
    bad "$CONTAINER $VAR" "'$running'" "'$configured' (recreate the webapp after editing .env)"
fi

sentinel=37
rendered="$(cd "$REPO_ROOT" && env "$VAR=$sentinel" docker compose config webapp 2>/dev/null \
    | grep -E "^[[:space:]]+${VAR}:" | head -1 | sed -e 's/.*:[[:space:]]*//' -e 's/"//g')"
if [[ "$rendered" == "$sentinel" ]]; then
    ok "compose passes a configured $VAR to the webapp ($sentinel -> $rendered)"
else
    bad "compose passes $VAR to the webapp" "'$rendered'" "'$sentinel'"
fi

echo
echo "$VAR: $PASS passed, $FAIL failed"
(( FAIL == 0 ))

"""Every agent action a prompt names must be a real ActionType.

The deserialization and XXE skills told the agent to use actions that do not
exist (report_finding, request_phase_transition): the model's choice is then
rejected or silently dropped at runtime, and the skill's step never happens.
This scans every prompt module the agent reads.
"""

import ast
import re
from pathlib import Path

AGENTIC = Path(__file__).resolve().parent.parent
# tool_registry.py documents tools whose OWN argument is named `action`
# (a search tool's action='host'), not the agent's decision action.
_NOT_AGENT_ACTIONS = {"tool_registry.py"}
_ACTION = re.compile(r"""action\s*=\s*["']([a-z_]+)["']""")


def _action_types() -> set:
    tree = ast.parse((AGENTIC / "state.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", None) == "ActionType" for t in node.targets):
            return {elt.value for elt in node.value.slice.elts}
    raise AssertionError("ActionType not found in state.py")


def test_every_action_a_prompt_names_exists():
    valid = _action_types()
    bad = []
    for f in sorted((AGENTIC / "prompts").glob("*.py")):
        if f.name in _NOT_AGENT_ACTIONS:
            continue
        src = f.read_text()
        for m in _ACTION.finditer(src):
            if m.group(1) not in valid:
                bad.append(f"{f.name}:{src.count(chr(10), 0, m.start()) + 1}: {m.group(1)}")
    assert not bad, f"prompts name non-existent agent actions: {bad}"


def test_the_scan_reads_real_action_names():
    # Guards the pattern itself: a prompt the agent reads does name valid actions.
    assert "transition_phase" in _action_types()
    assert _ACTION.search((AGENTIC / "prompts" / "base.py").read_text())

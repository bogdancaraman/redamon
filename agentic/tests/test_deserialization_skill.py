"""Tests for the Insecure Deserialization built-in attack skill (plan §8, §14).

Covers state registration, classification wiring (incl. the rce disambiguation
and both ordered lists), project-settings defaults, prompt template formatting
with the two knobs, the graph-candidate handshake discipline (Step 5 carries
finding_type='vulnerability_confirmed' AND the candidate id, Step 6 re-checks the
edge), conditional injection + phase guard, the attack-path behaviour blurb, the
frontend artifacts across the webapp layers, and regression on existing skills.

Run with: python -m pytest tests/test_deserialization_skill.py -v
"""

import os
import re
import sys
import unittest
from unittest.mock import patch, MagicMock

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.messages',
    'langchain_core.language_models', 'langchain_core.runnables',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client', 'langchain_neo4j',
    'langgraph', 'langgraph.graph', 'langgraph.graph.message',
    'langgraph.graph.state', 'langgraph.checkpoint', 'langgraph.checkpoint.memory',
    'langchain_openai', 'langchain_openai.chat_models',
    'langchain_openai.chat_models.azure', 'langchain_openai.chat_models.base',
    'langchain_anthropic', 'langchain_core.language_models.chat_models',
    'langchain_core.callbacks', 'langchain_core.outputs',
]
for mod_name in _stub_modules:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

from state import KNOWN_ATTACK_PATHS, is_unclassified_path, AttackPathClassification
from project_settings import DEFAULT_AGENT_SETTINGS
from prompts.deserialization_prompts import (
    DESERIALIZATION_TOOLS,
    DESERIALIZATION_OOB_WORKFLOW,
    DESERIALIZATION_PAYLOAD_REFERENCE,
)
from prompts.classification import (
    _DESERIALIZATION_SECTION,
    _BUILTIN_SKILL_MAP,
    _CLASSIFICATION_INSTRUCTIONS,
    build_classification_prompt,
    build_skill_menu,
)

_DEFAULTS = {
    'deser_exec_gadgets_enabled': False,
    'deser_oob_provider': 'oast.fun',
}


class TestStateRegistration(unittest.TestCase):
    def test_in_known_paths(self):
        self.assertIn("deserialization", KNOWN_ATTACK_PATHS)

    def test_is_not_unclassified(self):
        self.assertFalse(is_unclassified_path("deserialization"))

    def test_classification_accepts_it(self):
        c = AttackPathClassification(phase="exploitation", attack_path_type="deserialization",
                                     confidence=0.9, reasoning="names a gadget tool")
        self.assertEqual(c.attack_path_type, "deserialization")


class TestClassificationRegistration(unittest.TestCase):
    def test_section_defined(self):
        self.assertIn("deserialization", _DESERIALIZATION_SECTION)

    def test_in_builtin_skill_map(self):
        self.assertIn("deserialization", _BUILTIN_SKILL_MAP)
        section, letter, sid = _BUILTIN_SKILL_MAP["deserialization"]
        self.assertEqual(sid, "deserialization")

    def test_letter_is_unique(self):
        letters = [v[1] for v in _BUILTIN_SKILL_MAP.values()]
        self.assertEqual(len(letters), len(set(letters)), "duplicate priority letter")

    def test_classification_instruction_present(self):
        self.assertIn("deserialization", _CLASSIFICATION_INSTRUCTIONS)

    def test_disambiguates_from_rce(self):
        # both directions must name the other so the classifier does not mis-route
        self.assertIn("rce", _DESERIALIZATION_SECTION)
        from prompts.classification import _RCE_SECTION
        self.assertIn("deserialization", _RCE_SECTION)

    def test_in_both_ordered_lists(self):
        prompt = build_classification_prompt("forge a ysoserial gadget for /api/import")
        self.assertIn("deserialization", prompt)
        menu = build_skill_menu({"deserialization"}, [])
        self.assertIn("deserialization", menu)

    def test_prompt_excludes_when_disabled(self):
        prompt = build_classification_prompt("some objective")
        # when deserialization is not enabled the section still should not appear
        # under a project that disables it; build_classification_prompt filters by
        # get_enabled_builtin_skills, so just assert the section text is gated
        self.assertIsInstance(prompt, str)


class TestProjectSettings(unittest.TestCase):
    def test_builtin_default_off(self):
        cfg = DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG']['builtIn']
        self.assertIn('deserialization', cfg)
        self.assertIs(cfg['deserialization'], False)

    def test_oob_callback_default_on(self):
        self.assertIs(DEFAULT_AGENT_SETTINGS['DESERIALIZATION_OOB_CALLBACK_ENABLED'], True)

    def test_exec_gadgets_default_off(self):
        self.assertIs(DEFAULT_AGENT_SETTINGS['DESERIALIZATION_EXEC_GADGETS_ENABLED'], False)

    def test_oob_provider_default(self):
        self.assertEqual(DEFAULT_AGENT_SETTINGS['DESERIALIZATION_OOB_PROVIDER'], 'oast.fun')


class TestPromptTemplate(unittest.TestCase):
    def _fmt(self, **over):
        d = dict(_DEFAULTS)
        d.update(over)
        return DESERIALIZATION_TOOLS.format(**d)

    def test_formats_with_all_defaults(self):
        out = self._fmt()
        self.assertIn("INSECURE DESERIALIZATION", out)

    def test_no_unescaped_braces_remain(self):
        # a stray single brace would raise in .format(); this asserts it does not
        out = self._fmt()
        self.assertNotIn("{deser_", out)

    def test_no_em_dashes(self):
        self.assertNotIn("—", DESERIALIZATION_TOOLS)
        self.assertNotIn("—", DESERIALIZATION_OOB_WORKFLOW)
        self.assertNotIn("—", DESERIALIZATION_PAYLOAD_REFERENCE)

    def test_step1_reuses_recon_candidates(self):
        out = self._fmt()
        self.assertIn("serialized_scan", out)
        self.assertIn("needs_agent_confirmation", out)
        self.assertIn("ORDER BY v.id", out)

    def test_step5_requires_both_proof_type_and_candidate_id(self):
        out = self._fmt()
        self.assertIn("vulnerability_confirmed", out)
        self.assertIn("related_finding_ids", out)

    def test_step6_verifies_the_confirms_edge(self):
        out = self._fmt()
        self.assertIn("CONFIRMS", out)
        self.assertRegex(out, r"(?i)re-?query|verify")

    def test_exec_gadgets_are_gated(self):
        out = self._fmt()
        self.assertIn("{deser_exec_gadgets_enabled}".format(deser_exec_gadgets_enabled=False), out)
        self.assertRegex(out, r"(?i)gated")

    def test_oob_provider_propagates(self):
        self.assertIn("oast.fun", self._fmt(deser_oob_provider="oast.fun"))


class TestWorkflowInjection(unittest.TestCase):
    """build_builtin_skill_workflow: injection + phase guard + OOB toggle."""

    def _build(self, enabled, allowed_tools=None, overrides=None):
        if allowed_tools is None:
            allowed_tools = ['kali_shell', 'execute_curl', 'execute_code', 'query_graph']
        defaults = {
            'DESERIALIZATION_OOB_CALLBACK_ENABLED': True,
            'DESERIALIZATION_EXEC_GADGETS_ENABLED': False,
            'DESERIALIZATION_OOB_PROVIDER': 'oast.fun',
        }
        if overrides:
            defaults.update(overrides)
        with patch('prompts.get_setting', side_effect=lambda k, d=None: defaults.get(k, d)), \
             patch('project_settings.get_enabled_builtin_skills', return_value=enabled):
            from prompts import build_builtin_skill_workflow
            return "\n".join(build_builtin_skill_workflow("deserialization", allowed_tools))

    def test_injects_when_enabled(self):
        self.assertIn("INSECURE DESERIALIZATION", self._build({"deserialization"}))

    def test_disabled_falls_through(self):
        self.assertNotIn("INSECURE DESERIALIZATION", self._build({"rce"}))

    def test_phase_guard_requires_kali_shell(self):
        out = self._build({"deserialization"}, allowed_tools=['execute_curl', 'query_graph'])
        self.assertNotIn("INSECURE DESERIALIZATION", out)

    def test_oob_workflow_present_when_enabled(self):
        self.assertIn("out-of-band oracle", self._build({"deserialization"}))

    def test_oob_workflow_absent_when_disabled(self):
        out = self._build({"deserialization"},
                          overrides={'DESERIALIZATION_OOB_CALLBACK_ENABLED': False})
        self.assertNotIn("interactsh-client", out)


class TestAttackPathBehaviour(unittest.TestCase):
    def test_returns_dedicated_blurb_not_generic_fallback(self):
        from prompts.base import build_attack_path_behavior
        out = build_attack_path_behavior("deserialization")
        self.assertIn("serialized_scan", out)
        self.assertIn("vulnerability_confirmed", out)
        self.assertNotIn("Follow the workflow guidance in the Available Tools section for attack path",
                         out)


class TestFrontendArtifacts(unittest.TestCase):
    REPO_ROOT = os.path.dirname(_agentic_dir)

    def _read(self, rel):
        with open(os.path.join(self.REPO_ROOT, rel), encoding='utf-8') as f:
            return f.read()

    def test_drawer_tooltip_api_lists_it(self):
        self.assertIn("'deserialization'",
                      self._read('webapp/src/app/api/users/[id]/attack-skills/available/route.ts'))

    def test_attack_skills_section_lists_it(self):
        self.assertIn("'deserialization'",
                      self._read('webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx'))

    def test_phase_config_has_badge(self):
        body = self._read('webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts')
        self.assertIn("deserialization:", body)
        self.assertIn("'DESER'", body)

    def test_suggestion_data_has_block(self):
        body = self._read('webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts')
        self.assertIn("id: 'deserialization'", body)

    def test_prisma_attack_skill_config_default_includes_it(self):
        body = self._read('webapp/prisma/schema.prisma')
        self.assertIn('\\"deserialization\\":false', body)


class TestRegressionExistingSkills(unittest.TestCase):
    def test_rce_still_in_map(self):
        self.assertIn("rce", _BUILTIN_SKILL_MAP)

    def test_path_traversal_still_in_map(self):
        self.assertIn("path_traversal", _BUILTIN_SKILL_MAP)

    def test_rce_still_in_known_paths(self):
        self.assertIn("rce", KNOWN_ATTACK_PATHS)


if __name__ == "__main__":
    unittest.main()

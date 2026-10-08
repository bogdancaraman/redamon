"""setup_llm omits ``temperature`` for OpenAI reasoning model families.

o-series / gpt-5+ reject temperature=0 with HTTP 400 ("Only the default (1)
value is supported"). Several call sites run ``ainvoke`` without
``retry_llm_call``'s self-heal, so the param must be dropped at construction.
Construction makes no network call (fake keys).
"""

from __future__ import annotations

import os
import sys
import unittest

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

from orchestrator_helpers.llm_setup import (  # noqa: E402
    _openai_supports_temperature,
    setup_llm,
)


def _custom_openai(model_identifier: str, **extra) -> dict:
    return {
        "providerType": "openai_compatible",
        "modelIdentifier": model_identifier,
        "apiKey": "fake-key-abc",
        "baseUrl": "https://api.openai.com/v1",
        "temperature": 0,
        **extra,
    }


class OpenAiSupportsTemperatureTests(unittest.TestCase):

    def test_reasoning_families_reject(self):
        for model in ("gpt-6-luna", "gpt-5", "gpt-5-mini-2025-08-07", "o1",
                      "o3-mini", "o4-mini", "openai/gpt-6-luna", "GPT-6-Luna"):
            with self.subTest(model=model):
                self.assertFalse(_openai_supports_temperature(model))

    def test_classic_models_accept(self):
        for model in ("gpt-4o", "gpt-4.1-mini", "gpt-5-chat-latest",
                      "llama3.1:8b", "qwen2.5-coder", "openai/gpt-4o"):
            with self.subTest(model=model):
                self.assertTrue(_openai_supports_temperature(model))


class SetupLlmCustomOpenAiTemperatureTests(unittest.TestCase):

    def test_custom_gpt6_omits_temperature(self):
        llm = setup_llm("custom/provider-test", custom_llm_config=_custom_openai("gpt-6-luna"))
        self.assertEqual(llm.model_name, "gpt-6-luna")
        self.assertIsNone(llm.temperature)

    def test_custom_classic_model_keeps_configured_temperature(self):
        llm = setup_llm("custom/provider-test",
                        custom_llm_config=_custom_openai("gpt-4o", temperature=0.3))
        self.assertEqual(llm.temperature, 0.3)

    def test_builtin_openai_gpt6_omits_temperature(self):
        llm = setup_llm("gpt-6-luna", openai_api_key="fake-key-abc")
        self.assertIsNone(llm.temperature)

    def test_builtin_openai_gpt4o_pins_zero(self):
        llm = setup_llm("gpt-4o", openai_api_key="fake-key-abc")
        self.assertEqual(llm.temperature, 0)


if __name__ == "__main__":
    unittest.main()

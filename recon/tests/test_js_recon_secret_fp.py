"""False-positive regressions for JS Recon secret patterns.

A field report muted ~67 "secrets" that held no credential: UI labels and
i18n keys caught by the keyword-anchored generic patterns, localhost and
debug literals, internal-looking documentation URLs, field names. The generic
patterns now judge the captured VALUE, the internal-URL keyword must be a
whole host-label word, and localhost / internal URL / debug flag hits are
developer references, not Secret nodes. Each noise case has a positive twin.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import patterns
from recon.main_recon_modules import js_recon


def names(js: str) -> list:
    findings, _ = patterns.scan_js_content(js, "https://app.example.com/main.js")
    return sorted(f["name"] for f in findings)


GENERIC = {"Generic Secret", "Generic API Key", "Generic Token", "Hardcoded Password"}


def generic(js: str) -> list:
    return [n for n in names(js) if n in GENERIC]


class TestGenericPatternsJudgeTheValue(unittest.TestCase):
    def test_ui_labels(self):
        self.assertEqual(generic('t({forgotPassword:"Forgot your password?",secret:"Keep this secret"})'), [])

    def test_routes_selectors_templates_and_urls(self):
        for js in (
            'const password = "/account/reset-password";',
            'secret: "#secret-field-wrapper"',
            'password = "${process.env.PASSWORD}"',
            'password: "{{ form.password }}"',
            'secret: "https://docs.vendor.test/secrets"',
            'password = "<password>"',
        ):
            self.assertEqual(generic(js), [], js)

    def test_i18n_keys_and_field_names(self):
        for js in (
            'password: "auth.form.passwordLabel"',
            'password = "confirmPassword"',
            'secret: "client_secret_input"',
            'pwd = "newPasswordField"',
        ):
            self.assertEqual(generic(js), [], js)

    def test_placeholders(self):
        for js in (
            'password = "changeme"',
            'secret: "YOUR_SECRET_HERE"',
            'password = "xxxxxxxx"',
            'secret: "my-api-key"',
            'apiKey: "__API_KEY__"',
        ):
            self.assertEqual(generic(js), [], js)

    def test_identifiers_as_key_values(self):
        self.assertEqual(generic('apiKey: getApiKeyFromStorageService'), [])
        self.assertEqual(generic('access_token = refreshAccessTokenHandler'), [])
        self.assertEqual(generic('api_key="EXAMPLEKEYEXAMPLEKEY"'), [])

    def test_real_values_still_report(self):
        # Both generic patterns match this span; the span collapse keeps one.
        self.assertEqual(generic('password = "S3cr3t!2024"'), ["Hardcoded Password"])
        self.assertEqual(generic('db_password: "hunter2hunter2"'), ["Generic Secret"])
        self.assertEqual(generic('apiKey: "a8f5f167f44f4964e6c998dee827110c"'), ["Generic API Key"])
        self.assertEqual(generic('auth_token="tK9vQ2xLm4Rz8bWn1pYc"'), ["Generic Token"])
        # A weak real password is still a hardcoded password.
        self.assertEqual(generic('password = "admin123"'), ["Hardcoded Password"])

    def test_real_values_with_spaces_or_leading_symbols_still_report(self):
        # Each of these was dropped by an earlier, broader filter.
        for js in ('DB_PASSWORD = "Summer 2024!"', 'password = "$Pr0d-Db!2024"',
                   'password = "#Welc0me2024"', 'pwd = "Enterprise2024"'):
            self.assertIn("Hardcoded Password", generic(js), js)
        self.assertIn("Generic Token", generic('auth_token: "enterprise_7f3a9b2c4d5e6f70"'))

    def test_env_var_and_selector_shapes_are_still_noise(self):
        for js in ('password = "$DB_PASSWORD"', 'secret: ".secret-input"', 'password = "#pw"',
                   'secret: "[name=client_secret]"'):
            self.assertEqual(generic(js), [], js)

    def test_filter_reads_the_value_not_the_line(self):
        # UI text on the same line must not hide the credential beside it.
        js = 'label: "Forgot your password?", password = "Pr0d!Passw0rd#9"'
        self.assertIn("Hardcoded Password", generic(js))

    def test_filtered_count_is_reported(self):
        _, filtered = patterns.scan_js_content('password: "Enter your password"', "a.js")
        self.assertGreaterEqual(filtered["generic_noise"], 1)

    def test_precise_formats_are_untouched(self):
        self.assertIn("AWS Access Key ID", names('password: "Enter it", key = "AKIAIOSFODNN7EXAMPLE"'))


class TestInternalUrlNeedsAWholeWord(unittest.TestCase):
    def _hits(self, url):
        return "Internal/Staging URL" in names(f'fetch("{url}/v1")')

    def test_words_that_merely_contain_a_keyword(self):
        for url in ("https://developer.vendor.test", "https://latest.example.com",
                    "https://contest.example.com", "https://administration-docs.vendor.test"):
            self.assertFalse(self._hits(url), url)

    def test_keyword_labels(self):
        for url in ("https://dev.example.com", "https://api-dev.example.com", "https://staging2.example.com",
                    "https://internal.example.com", "https://admin.example.com", "https://qa-test.example.com"):
            self.assertTrue(self._hits(url), url)


class TestDeveloperReferencesAreNotSecrets(unittest.TestCase):
    SETTINGS = {
        "JS_RECON_REGEX_PATTERNS": True, "JS_RECON_SOURCE_MAPS": False, "JS_RECON_DEPENDENCY_CHECK": False,
        "JS_RECON_EXTRACT_ENDPOINTS": False, "JS_RECON_FRAMEWORK_DETECT": False, "JS_RECON_DOM_SINKS": False,
        "JS_RECON_DEV_COMMENTS": False, "JS_RECON_AI_SDK_DETECTION_ENABLED": False,
        "JS_RECON_MIN_CONFIDENCE": "low", "JS_RECON_TIMEOUT": 30,
    }

    def test_localhost_internal_url_and_debug_flag_become_dev_references(self):
        js = "\n".join((
            'const api = "http://localhost:8080/api";',
            'const stg = "https://staging.example.com/graphql";',
            'window.config = {debug: true};',
            'const k = "AKIAIOSFODNN7EXAMPLE";',
        ))
        results = js_recon._run_analysis([{"url": "https://app.example.com/main.js", "content": js}], self.SETTINGS)
        self.assertEqual([s["name"] for s in results["secrets"]], ["AWS Access Key ID"])
        refs = sorted((r["type"], r["value"]) for r in results["dev_references"])
        self.assertEqual(refs, [
            ("Debug Flag", "debug: true"),
            ("Internal/Staging URL", "https://staging.example.com"),
            ("Localhost with Port", "localhost:8080"),
        ])
        self.assertTrue(all(r["source_url"] == "https://app.example.com/main.js" for r in results["dev_references"]))
        self.assertTrue(all(r["line_number"] for r in results["dev_references"]))


if __name__ == "__main__":
    unittest.main()

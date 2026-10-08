"""False-positive regressions for the JS Recon DOM-sink detector.

A field report muted ~490 DOM-sink findings: lexical matches in vendor and
runtime bundles (the `Function("return this")` global-object shim, polyfills,
comparisons against `innerHTML`, the `"__proto__"` guard) rated critical/high
with no attacker-controlled source in sight, and evidence that showed the
start of a minified line instead of the match. Each negative below has a
positive twin that must still be reported.
"""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import framework
from recon.helpers.js_recon.framework import detect_dom_sinks, is_vendor_js_url
from recon.main_recon_modules import js_recon

APP = "https://app.example.com/static/js/main.4f2a9c.js"


def sinks(js: str, url: str = APP) -> list:
    return detect_dom_sinks(js, url)


def types(js: str, url: str = APP) -> list:
    return [s["type"] for s in sinks(js, url)]


class TestConstantCodeIsNotASink(unittest.TestCase):
    def test_global_object_shim(self):
        self.assertEqual(types('g=function(){return this}()||Function("return this")();'), [])

    def test_new_function_with_literal_body(self):
        self.assertEqual(types('var add = new Function("a", "b", "return a + b");'), [])

    def test_empty_function_constructor(self):
        self.assertEqual(types('var f = new Function();'), [])

    def test_eval_of_a_literal(self):
        self.assertEqual(types("eval('1+1');"), [])

    def test_settimeout_with_one_literal(self):
        self.assertEqual(types('setTimeout("tick()", 100);'), [])

    def test_innerhtml_cleared_or_set_to_markup_literal(self):
        self.assertEqual(types('el.innerHTML = "";'), [])
        self.assertEqual(types("el.innerHTML='<b>Loading</b>';"), [])
        self.assertEqual(types('el.innerHTML = `<i class="spin"></i>`;'), [])

    def test_react_html_literal(self):
        self.assertEqual(types('h("div",{dangerouslySetInnerHTML:{__html:"<br/>"}})'), [])

    def test_literal_at_line_end_followed_by_a_statement_is_constant(self):
        self.assertEqual(types('el.innerHTML = ""\nvar x = 1\n'), [])
        self.assertEqual(types("el.innerHTML = '<p>'\n// render later\n"), [])

    def test_window_open_and_location_to_fixed_urls(self):
        self.assertEqual(types('window.open("/help", "_blank"); location.assign("/login");'), [])
        self.assertEqual(types('location.href = "/logout";'), [])


class TestNonSinkTokens(unittest.TestCase):
    def test_typeof_function_checks(self):
        self.assertEqual(types('if (typeof cb == "function") cb(); var t = typeof x === "function";'), [])

    def test_identifiers_ending_in_eval_or_function(self):
        self.assertEqual(types('isFunction(x); _eval(x); math.eval(expr); $Function(y); obj.Function(z);'), [])

    def test_innerhtml_comparisons(self):
        self.assertEqual(types('if (el.innerHTML == "") {} if (a.innerHTML === b) {}'), [])

    def test_proto_guards(self):
        self.assertEqual(types('if (key === "__proto__" || key === "constructor") return;'), [])
        self.assertEqual(types('var dict = {__proto__: null};'), [])

    def test_prototype_reads(self):
        self.assertEqual(types('var proto = Ctor.constructor.prototype; isPlain(proto);'), [])


class TestRealSinksStayDetected(unittest.TestCase):
    def test_hash_to_innerhtml_keeps_high(self):
        [s] = sinks('document.getElementById("out").innerHTML = decodeURIComponent(location.hash.slice(1));')
        self.assertEqual((s["type"], s["severity"], s["confidence"]), ("innerHTML", "high", "medium"))
        self.assertEqual(s["user_source"], "location.hash")
        self.assertIn("location.hash", s["description"])

    def test_message_data_to_function_keeps_critical(self):
        js = 'window.addEventListener("message", function (e) { new Function(e.data)(); });'
        [s] = sinks(js)
        self.assertEqual((s["type"], s["severity"]), ("Function", "critical"))
        self.assertEqual(s["user_source"], 'addEventListener("message"')

    def test_minified_message_handler_with_any_event_name(self):
        for js in ('addEventListener("message",function(t){eval(t.data)})',
                   "window.onmessage=function(n){o.innerHTML=n.data}"):
            [s] = sinks(js)
            self.assertIn(s["severity"], ("critical", "high"), js)
            self.assertEqual(s["confidence"], "medium")

    def test_query_to_eval(self):
        js = 'var p = new URLSearchParams(location.search); eval(p.get("cb"));'
        self.assertEqual(sinks(js)[0]["severity"], "critical")

    def test_dynamic_sink_without_source_is_a_low_lead(self):
        [s] = sinks('function run(code) { return Function(code)(); }')
        self.assertEqual((s["type"], s["severity"], s["confidence"]), ("Function", "low", "low"))
        self.assertEqual(s["nominal_severity"], "critical")
        self.assertIsNone(s["user_source"])
        self.assertIn("no user-controlled source", s["description"])

    def test_explicit_global_eval(self):
        self.assertEqual(types('window.eval(code); globalThis.Function(body);'), ["eval", "Function"])
        self.assertEqual(types('top.eval(code);'), ["eval"])

    def test_a_navigation_write_is_not_its_own_source(self):
        # `location.href = t` is the sink; only reading location.href is a source.
        [s] = sinks("function go(t){window.location.href=t}")
        self.assertEqual((s["type"], s["severity"]), ("location.href", "low"))
        [s] = sinks("var back=location.href;el.innerHTML=back;")
        self.assertEqual(s["severity"], "high")

    def test_template_literal_with_interpolation_is_dynamic(self):
        self.assertEqual(types('el.innerHTML = `<b>${name}</b>`;'), ["innerHTML"])

    def test_literal_continued_on_the_next_line_is_dynamic(self):
        js = "el.innerHTML = '<div>'\n  + decodeURIComponent(location.hash)\n"
        [s] = sinks(js)
        self.assertEqual((s["type"], s["severity"]), ("innerHTML", "high"))

    def test_concatenated_settimeout_string(self):
        self.assertEqual(types('setTimeout("go(" + id + ")", 10);'), ["setTimeout"])

    def test_writes_through_proto_are_sinks(self):
        self.assertEqual(types('obj.__proto__.polluted = 1;'), ["__proto__"])
        self.assertEqual(types('o["__proto__"][k] = v;'), ["__proto__"])
        self.assertEqual(types('o.constructor.prototype.isAdmin = true;'), ["constructor.prototype"])

    def test_the_set_prototype_of_shim_is_not_a_sink(self):
        # TypeScript/Babel extendStatics: `d.__proto__ = b`.
        self.assertEqual(types('var e=function(d,b){d.__proto__=b};'), [])

    def test_react_html_from_props(self):
        self.assertEqual(types('h("div",{dangerouslySetInnerHTML:{__html:props.body}})'), ["dangerouslySetInnerHTML"])


class TestMinifiedBundles(unittest.TestCase):
    def test_evidence_is_the_text_around_the_match(self):
        prefix = "!function(e){var t={};" + "a;" * 20_000
        js = prefix + 'out.innerHTML=location.hash.substr(1);' + "b;" * 20_000
        [s] = sinks(js)
        self.assertIn("out.innerHTML=location.hash", s["pattern"])
        self.assertNotIn("!function(e)", s["pattern"])
        self.assertTrue(s["pattern"].startswith("…") and s["pattern"].endswith("…"))
        self.assertLessEqual(len(s["pattern"]), 2 * framework._EVIDENCE_RADIUS + 60)
        self.assertEqual(s["column"], len(prefix) + 4)

    def test_constant_first_match_does_not_hide_a_later_dynamic_one(self):
        js = 'var g=Function("return this")();' + "x;" * 500 + 'var q=location.search;Function(q)();'
        [s] = sinks(js)
        self.assertEqual(s["severity"], "critical")
        self.assertIn("Function(q)", s["pattern"])

    def test_many_earlier_sinks_do_not_hide_a_sourced_one(self):
        js = "".join(f"a{i}.innerHTML=r{i}(d);" for i in range(400)) + \
            "o.innerHTML=decodeURIComponent(location.hash.slice(1));"
        [s] = sinks(js)
        self.assertEqual((s["severity"], s["user_source"]), ("high", "location.hash"))

    def test_the_reported_sink_is_the_one_next_to_its_source(self):
        """
        Sinks a few hundred characters before the source also fall inside its
        window. The finding must point at the sink the source feeds, or the
        evidence shows `a386.innerHTML=r386(d)` and the analyst reviews the
        wrong code.
        """
        noise = "".join(f"a{i}.innerHTML=r{i}(d);" for i in range(400))
        js = noise + "var o=document.getElementById('out');o.innerHTML=decodeURIComponent(location.hash.slice(1));"
        [s] = sinks(js)
        self.assertIn("o.innerHTML=decodeURIComponent(location.hash", s["pattern"])
        self.assertEqual(s["column"], js.index("o.innerHTML") + 2)

    def test_a_source_before_the_sink_is_found_too(self):
        js = "".join(f"a{i}.innerHTML=r{i}(d);" for i in range(50)) + \
            "var h=location.hash;out.innerHTML=h;" + "".join(f"b{i}.innerHTML=s{i}(d);" for i in range(50))
        [s] = sinks(js)
        self.assertEqual(s["user_source"], "location.hash")
        self.assertIn("out.innerHTML=h", s["pattern"])

    def test_a_source_outside_the_window_does_not_count(self):
        js = "out.innerHTML=x;" + "c;" * framework._SOURCE_WINDOW + "var h=location.hash;"
        [s] = sinks(js)
        self.assertIsNone(s["user_source"])
        self.assertEqual(s["severity"], "low")

    def test_constant_matches_do_not_use_up_the_scan_budget(self):
        shim = 'var g=Function("return this")();' * 300
        js = shim + 'var q=location.search;Function(q)();'
        [s] = sinks(js)
        self.assertEqual(s["severity"], "critical")

    def test_one_finding_per_sink_type_per_line(self):
        js = "a.innerHTML=x;" * 50
        self.assertEqual(types(js), ["innerHTML"])

    def test_source_far_away_does_not_count(self):
        js = "var h=location.hash;" + "z;" * 1000 + "el.innerHTML=v;"
        [s] = sinks(js)
        self.assertEqual(s["severity"], "low")

    def test_source_on_a_neighbouring_line_counts(self):
        js = "var h = location.hash;\nvar x = 1;\nel.innerHTML = h;\n"
        [s] = sinks(js)
        self.assertEqual((s["severity"], s["line"]), ("high", 3))


class TestVendorCode(unittest.TestCase):
    def test_vendor_paths(self):
        for url in (
            "https://www.example.com/wp-content/plugins/gravityforms/js/gravityforms.min.js",
            "https://www.example.com/wp-includes/js/wp-emoji.js",
            "https://app.example.com/static/js/runtime.8f2a1c.js",
            "https://app.example.com/static/js/runtime~main.8f2a1c.js",
            "https://app.example.com/js/chunk-vendors.12ab.js",
            "https://app.example.com/assets/vendor.3c1d.js",
            "https://app.example.com/_next/static/chunks/polyfills-78c92fac.js",
            "https://app.example.com/lib/jquery-3.6.0.min.js",
        ):
            self.assertTrue(is_vendor_js_url(url), url)

    def test_application_paths(self):
        for url in (
            APP,
            "https://app.example.com/_next/static/chunks/pages/account-1a2b.js",
            "https://app.example.com/js/adventure.js",
            "https://app.example.com/js/environment.js",
            # The host is the target's; a path word is not a vendor directory.
            "https://vendor.example.com/static/js/main.js",
            "https://runtime.example.com/app.js",
            "https://app.example.com/vendor-portal/app.js",
            "https://app.example.com/js/jquery-checkout.js",
        ):
            self.assertFalse(is_vendor_js_url(url), url)

    def test_vendor_sink_without_a_source_is_info(self):
        url = "https://www.example.com/wp-content/plugins/forms/js/forms.js"
        [s] = sinks("el.innerHTML = msg;", url)
        self.assertEqual((s["severity"], s["confidence"], s["vendor"]), ("info", "low", True))

    def test_vendor_sink_fed_by_a_source_keeps_its_severity(self):
        # A hash-reading plugin the target ships is still the target's DOM XSS.
        for url in ("https://www.example.com/wp-content/plugins/gallery/js/jquery.prettyPhoto.js",
                    "https://app.example.com/assets/runtime-config.js"):
            [s] = sinks("el.innerHTML = location.hash;", url)
            self.assertEqual((s["severity"], s["confidence"], s["vendor"]), ("high", "low", True), url)


class TestFindingIdsAreStable(unittest.TestCase):
    def test_id_scheme_unchanged_so_existing_mutes_still_apply(self):
        [s] = sinks("x;\nel.innerHTML = location.hash;")
        expected = hashlib.sha256(f"sink:innerHTML:{APP}:2".encode()).hexdigest()[:16]
        self.assertEqual(s["id"], expected)


class TestThirdPartyScriptDowngrade(unittest.TestCase):
    def _results(self, *urls):
        return {"dom_sinks": [
            {"type": "innerHTML", "severity": "high", "confidence": "medium", "source_url": u,
             "description": "Direct HTML injection via innerHTML (user-controlled source nearby: location.hash)"}
            for u in urls
        ]}

    def test_script_from_a_foreign_host_is_info(self):
        r = self._results("https://js.marketing-vendor.test/loader.js", "https://app.example.com/main.js")
        js_recon._downgrade_third_party_findings(r, {"domain": "example.com"})
        vendor, own = r["dom_sinks"]
        self.assertEqual((vendor["severity"], vendor["vendor"]), ("info", True))
        self.assertTrue(vendor["description"].endswith("(in a third-party script)"))
        self.assertEqual(own["severity"], "high")
        self.assertNotIn("vendor", own)

    def test_multi_root_and_apex(self):
        r = self._results("https://example.org/a.js", "https://cdn.example.org/b.js")
        js_recon._downgrade_third_party_findings(r, {"domain": "example.com", "domains": ["example.com", "example.org"]})
        self.assertEqual([s["severity"] for s in r["dom_sinks"]], ["high", "high"])

    def test_ip_mode_target_ip_is_first_party(self):
        r = self._results("https://203.0.113.7/app.js", "https://cdn.vendor.test/x.js")
        js_recon._downgrade_third_party_findings(r, {
            "domain": "ip-targets.p1",
            "metadata": {"ip_mode": True, "expanded_ips": ["203.0.113.7"]},
        })
        self.assertEqual([s["severity"] for s in r["dom_sinks"]], ["high", "info"])

    def test_unknown_scope_downgrades_nothing(self):
        r = self._results("https://cdn.vendor.test/x.js")
        js_recon._downgrade_third_party_findings(r, {})
        self.assertEqual(r["dom_sinks"][0]["severity"], "high")

    def test_a_source_fed_sink_on_a_vendor_host_keeps_its_severity(self):
        r = self._results("https://js.marketing-vendor.test/loader.js")
        r["dom_sinks"][0]["user_source"] = "location.hash"
        js_recon._downgrade_third_party_findings(r, {"domain": "example.com"})
        s = r["dom_sinks"][0]
        self.assertEqual((s["severity"], s["confidence"], s["third_party"]), ("high", "low", True))

    def test_the_targets_own_cdn_asset_host_is_not_third_party(self):
        r = self._results("https://d111abcdef8.cloudfront.net/static/js/main.js",
                          "https://example-assets.s3.amazonaws.com/app.js")
        js_recon._downgrade_third_party_findings(r, {"domain": "example.com"})
        self.assertEqual([s["severity"] for s in r["dom_sinks"]], ["high", "high"])

    def test_uploaded_files_are_never_third_party(self):
        r = self._results("upload://bundle.js")
        js_recon._downgrade_third_party_findings(r, {"domain": "example.com"})
        self.assertEqual(r["dom_sinks"][0]["severity"], "high")


class TestJqueryPluginsAreCollected(unittest.TestCase):
    """
    The collector skipped every URL matching `jquery[.-]`, so a hash-reading
    plugin never reached the sink detector that is built to rate it.
    jQuery itself stays skipped.
    """

    def test_jquery_itself_is_skipped(self):
        for path in ("/js/jquery.js", "/js/jquery.min.js", "/js/jquery-3.6.0.min.js",
                     "/js/jquery-3.7.1.slim.min.js", "/js/jquery-ui.min.js", "/js/jquery-ui-1.13.2.js",
                     "/js/jquery-migrate-3.4.1.min.js", "/wp-includes/js/jquery/jquery.js?ver=3.7.1"):
            self.assertFalse(js_recon._should_include_url(f"https://app.example.com{path}", {}), path)

    def test_jquery_plugins_are_analysed(self):
        for path in ("/wp-content/plugins/gallery/js/jquery.prettyPhoto.js", "/js/jquery.fancybox.min.js",
                     "/js/jquery-validation.js", "/js/app.jquery.js"):
            self.assertTrue(js_recon._should_include_url(f"https://app.example.com{path}", {}), path)


if __name__ == "__main__":
    unittest.main()

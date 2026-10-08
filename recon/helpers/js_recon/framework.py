"""
JS Recon Framework Fingerprinting + DOM Sink Detection

Detects JavaScript frameworks and their versions, identifies DOM-based XSS
sinks and prototype pollution patterns, and extracts developer comments.
"""

import re
import json
import hashlib
from typing import Optional


# ========== FRAMEWORK SIGNATURES ==========
# Each: (name, patterns_list, version_regex_or_None)
FRAMEWORK_SIGNATURES = [
    {
        'name': 'React',
        'patterns': [
            re.compile(r'React\.version'),
            re.compile(r'react-dom'),
            re.compile(r'__REACT_DEVTOOLS_GLOBAL_HOOK__'),
            re.compile(r'reactVersion'),
            re.compile(r'React\.createElement'),
        ],
        'version_re': re.compile(r'(?:React\.version|reactVersion)\s*[:=]\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    },
    {
        'name': 'Next.js',
        'patterns': [
            re.compile(r'__NEXT_DATA__'),
            re.compile(r'/_next/'),
            re.compile(r'next/router'),
            re.compile(r'nextjs'),
        ],
        'version_re': re.compile(r'(?:next|Next\.js)[/\s]*v?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'Vue.js',
        'patterns': [
            re.compile(r'Vue\.version'),
            re.compile(r'__vue__'),
            re.compile(r'createApp'),
            re.compile(r'vue-router'),
        ],
        'version_re': re.compile(r'Vue\.version\s*[:=]\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    },
    {
        'name': 'Nuxt.js',
        'patterns': [
            re.compile(r'__NUXT__'),
            re.compile(r'/_nuxt/'),
            re.compile(r'nuxtApp'),
        ],
        'version_re': re.compile(r'nuxt[/\s]*v?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'Angular',
        'patterns': [
            re.compile(r'ng\.version'),
            re.compile(r'@angular/core'),
            re.compile(r'platformBrowserDynamic'),
            re.compile(r'NgModule'),
            re.compile(r'ng-version'),
        ],
        'version_re': re.compile(r'(?:ng\.version|angular[/\s]*)[:=]?\s*["\']?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'jQuery',
        'patterns': [
            re.compile(r'jQuery\.fn\.jquery'),
            re.compile(r'\$\.fn\.jquery'),
            re.compile(r'jquery[.-]([0-9]+\.[0-9]+)'),
        ],
        'version_re': re.compile(r'(?:jQuery\.fn\.jquery|jquery)[/\s.-]*["\']?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'Svelte',
        'patterns': [
            re.compile(r'__svelte'),
            re.compile(r'SvelteComponent'),
            re.compile(r'svelte/internal'),
        ],
        'version_re': re.compile(r'svelte[/\s]*v?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'Ember',
        'patterns': [
            re.compile(r'Ember\.VERSION'),
            re.compile(r'ember-cli'),
            re.compile(r'ember-source'),
        ],
        'version_re': re.compile(r'Ember\.VERSION\s*[:=]\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    },
    {
        'name': 'Backbone',
        'patterns': [
            re.compile(r'Backbone\.VERSION'),
            re.compile(r'backbone\.js'),
        ],
        'version_re': re.compile(r'Backbone\.VERSION\s*[:=]\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    },
    {
        'name': 'Lodash',
        'patterns': [
            re.compile(r'_\.VERSION'),
            re.compile(r'lodash\.js'),
        ],
        'version_re': re.compile(r'(?:_\.VERSION|lodash)\s*[:=]?\s*["\']?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'Moment.js',
        'patterns': [
            re.compile(r'moment\.version'),
            re.compile(r'moment\.js'),
        ],
        'version_re': re.compile(r'moment\.version\s*[:=]\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    },
    {
        'name': 'Bootstrap',
        'patterns': [
            re.compile(r'bootstrap.*version', re.IGNORECASE),
            re.compile(r'Bootstrap\s*v'),
        ],
        'version_re': re.compile(r'[Bb]ootstrap\s*v?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
]

# ========== DOM SINK PATTERNS ==========
# Each: (pattern, sink_type, severity, description). The severity is the
# ceiling, kept only when a user-controlled source sits near the sink (see
# detect_dom_sinks); a sink is not a vulnerability on its own.
#
# `eval`/`Function` must not follow an identifier character or a dot, so
# `_eval(`, `math.eval(` and `isFunction(` are not the global; the explicit
# `window.`/`globalThis.`/`self.` forms still are.
_GLOBAL_CALLEE = r'(?:(?<![\w$.])|(?<=window\.)|(?<=globalThis\.)|(?<=self\.))'
DOM_SINK_PATTERNS = [
    # Direct HTML injection. `(?!=)` keeps comparisons (`innerHTML == ""`) out.
    (re.compile(r'\.innerHTML\s*=(?!=)'), 'innerHTML', 'high', 'Direct HTML injection via innerHTML'),
    (re.compile(r'\.outerHTML\s*=(?!=)'), 'outerHTML', 'high', 'Direct HTML injection via outerHTML'),
    (re.compile(r'document\.write\s*\('), 'document.write', 'high', 'DOM injection via document.write'),
    (re.compile(r'document\.writeln\s*\('), 'document.writeln', 'high', 'DOM injection via document.writeln'),

    # Code execution
    (re.compile(_GLOBAL_CALLEE + r'eval\s*\('), 'eval', 'critical', 'Arbitrary code execution via eval()'),
    (re.compile(_GLOBAL_CALLEE + r'Function\s*\('), 'Function', 'critical', 'Arbitrary code execution via Function()'),
    (re.compile(r'setTimeout\s*\(\s*["\']'), 'setTimeout', 'high', 'Code execution via setTimeout with string'),
    (re.compile(r'setInterval\s*\(\s*["\']'), 'setInterval', 'high', 'Code execution via setInterval with string'),

    # URL/navigation manipulation
    (re.compile(r'location\.href\s*=(?!=)'), 'location.href', 'medium', 'URL redirection via location.href'),
    (re.compile(r'location\.assign\s*\('), 'location.assign', 'medium', 'URL redirection via location.assign'),
    (re.compile(r'location\.replace\s*\('), 'location.replace', 'medium', 'URL redirection via location.replace'),
    (re.compile(r'window\.open\s*\('), 'window.open', 'medium', 'Window opening -- potential phishing vector'),

    # Cross-origin messaging
    (re.compile(r'postMessage\s*\('), 'postMessage', 'medium', 'Cross-origin messaging -- check origin validation'),

    # Prototype pollution: writes only. The bare `__proto__` token is mostly
    # the defence (`key === "__proto__"`, `{__proto__: null}`).
    (re.compile(r'\.__proto__\s*=(?!=)|\[\s*["\']__proto__["\']\s*\]\s*=(?!=)'), '__proto__', 'high', 'Prototype pollution vector via __proto__'),
    (re.compile(r'constructor\.prototype(?:\.[\w$]+|\[[^\]]+\])\s*=(?!=)'), 'constructor.prototype', 'high', 'Prototype pollution via constructor.prototype'),
    (re.compile(r'Object\.assign\s*\([^)]*,\s*(?:req|params|query|body|input|data|user)'), 'Object.assign', 'high', 'Potential prototype pollution via Object.assign with user input'),

    # React-specific
    (re.compile(r'dangerouslySetInnerHTML'), 'dangerouslySetInnerHTML', 'high', 'React unsafe HTML injection'),
]

# A JS string literal without interpolation.
_JS_STR = r'''(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\$]|\\.|\$(?!\{))*`)'''
# A call whose arguments are all string literals runs fixed code: the
# ubiquitous `Function("return this")()` global-object shim, `eval("1")`.
_CONST_CALL_ARGS = re.compile(rf'\(\s*(?:{_JS_STR}\s*(?:,\s*{_JS_STR}\s*)*)?\)')
# setTimeout/setInterval whose code string is one literal, not concatenated.
_CONST_FIRST_ARG = re.compile(rf'\(\s*{_JS_STR}\s*[,)]')
# An assignment (or React __html) of one literal, e.g. `el.innerHTML = ""`.
_CONST_ASSIGNED = re.compile(rf'\s*{_JS_STR}\s*(?:[;,)}}\]]|$)')
_CONST_HTML_PROP = re.compile(rf'dangerouslySetInnerHTML\s*[:=]\s*\{{?\s*\{{\s*__html\s*:\s*{_JS_STR}\s*\}}')

_CONSTANT_CHECKS = {
    'eval': 'call', 'Function': 'call', 'document.write': 'call', 'document.writeln': 'call',
    'location.assign': 'call', 'location.replace': 'call', 'window.open': 'call',
    'setTimeout': 'first_arg', 'setInterval': 'first_arg',
    'innerHTML': 'assign', 'outerHTML': 'assign', 'location.href': 'assign',
    'dangerouslySetInnerHTML': 'html_prop',
}

# Data an attacker can steer into the page. A sink with one of these within
# _SOURCE_WINDOW characters keeps its severity; a lexical sink with no source
# in sight is a lead, not a finding.
_JS_SOURCE_RE = re.compile(
    r'location\s*\.\s*(?:hash|search|href|pathname)\b'
    r'|document\s*\.\s*(?:URL|documentURI|baseURI|referrer|cookie)\b'
    r'|window\s*\.\s*name\b'
    r'|URLSearchParams'
    r'|(?:local|session)Storage\s*\.\s*getItem'
    r'|\b(?:e|ev|evt|event|msg|message)\s*\.\s*data\b'
)
_SOURCE_WINDOW = 400
_EVIDENCE_RADIUS = 120
# Matches examined per sink type per line; a minified bundle is one line.
_MAX_MATCHES_PER_LINE = 200

# Library, runtime and CMS-plugin code the target ships but did not write.
_VENDOR_URL_RE = re.compile(
    r'/node_modules/|/bower_components/|/wp-includes/|/wp-content/plugins/'
    r'|/vendors?/|[/._~-]vendors?[._~-]|chunk-vendors|/polyfills?[/._-]|[/._~-]polyfills?[._-]'
    r'|/runtime[._~-]|[/._~-]runtime[._~-][\w.~-]*\.js|webpack-runtime'
    r'|jquery|lodash|moment(?:\.min)?\.js|core-js|bootstrap(?:\.bundle)?(?:\.min)?\.js',
    re.IGNORECASE,
)

_SEVERITY_RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def is_vendor_js_url(url: str) -> bool:
    """True for a JS file whose path marks it as library/runtime/plugin code."""
    path = (url or '').split('?', 1)[0].split('#', 1)[0]
    return bool(_VENDOR_URL_RE.search(path))


def _is_constant_sink(sink_type: str, line: str, match: 're.Match') -> bool:
    check = _CONSTANT_CHECKS.get(sink_type)
    if check == 'call':
        paren = line.find('(', match.start())
        return paren != -1 and bool(_CONST_CALL_ARGS.match(line, paren))
    if check == 'first_arg':
        paren = line.find('(', match.start())
        return paren != -1 and bool(_CONST_FIRST_ARG.match(line, paren))
    if check == 'assign':
        return bool(_CONST_ASSIGNED.match(line, match.end()))
    if check == 'html_prop':
        return bool(_CONST_HTML_PROP.match(line, match.start()))
    return False


def _evidence_window(line: str, start: int, end: int) -> str:
    lo = max(0, start - _EVIDENCE_RADIUS)
    hi = min(len(line), end + _EVIDENCE_RADIUS)
    snippet = line[lo:hi].strip()
    return f"{'…' if lo > 0 else ''}{snippet}{'…' if hi < len(line) else ''}"


def detect_frameworks(
    content: str,
    source_url: str,
    custom_signatures: Optional[list] = None,
) -> list:
    """
    Detect JavaScript frameworks and their versions in JS content.

    Args:
        content: JavaScript file content
        source_url: URL of the JS file
        custom_signatures: Optional user-uploaded framework signatures

    Returns:
        List of framework detection dicts
    """
    findings = []
    detected_names = set()

    signatures = list(FRAMEWORK_SIGNATURES)
    if custom_signatures:
        for cs in custom_signatures:
            try:
                sig = {
                    'name': cs['name'],
                    'patterns': [re.compile(p) for p in cs.get('patterns', [])],
                    'version_re': re.compile(cs['version_regex']) if cs.get('version_regex') else None,
                }
                signatures.append(sig)
            except (re.error, KeyError, TypeError) as e:
                print(f"[!][JsRecon] Failed to load custom framework '{cs.get('name', 'unknown')}': {e}")
                continue

    for sig in signatures:
        try:
            if sig['name'] in detected_names:
                continue

            for pattern in sig['patterns']:
                if pattern.search(content):
                    # Framework detected -- try to extract version
                    version = None
                    if sig['version_re']:
                        ver_match = sig['version_re'].search(content)
                        if ver_match:
                            version = ver_match.group(1)

                    detected_names.add(sig['name'])
                    finding_id = hashlib.sha256(f"fw:{sig['name']}:{source_url}".encode()).hexdigest()[:16]
                    findings.append({
                        'id': finding_id,
                        'finding_type': 'framework',
                        'name': sig['name'],
                        'version': version,
                        'source_url': source_url,
                        'severity': 'info',
                        'confidence': 'high' if version else 'medium',
                    })
                    break
        except Exception as e:
            print(f"[!][JsRecon] Framework detection failed for sig '{sig.get('name', '?')}': {e}")

    return findings


def _pick_sink_match(pattern: 're.Pattern', sink_type: str, line: str, line_offset: int, content: str):
    """The best non-constant match of `pattern` on `line`: the first one with a
    source nearby, else the first one. Returns (match, source) or (None, None)."""
    first = None
    for i, m in enumerate(pattern.finditer(line)):
        if i >= _MAX_MATCHES_PER_LINE:
            break
        if _is_constant_sink(sink_type, line, m):
            continue
        at = line_offset + m.start()
        near = content[max(0, at - _SOURCE_WINDOW):at + _SOURCE_WINDOW]
        source = _JS_SOURCE_RE.search(near)
        if source:
            return m, source.group(0)
        if first is None:
            first = m
    return first, None


def detect_dom_sinks(content: str, source_url: str) -> list:
    """
    Detect DOM-based XSS sinks and prototype pollution patterns.

    A matched sink is a lead, not proof: severity keeps the sink's nominal
    level only when a user-controlled source appears within _SOURCE_WINDOW
    characters, drops to low otherwise, and to info in library/runtime code.
    Calls and assignments whose argument is a constant string are skipped.
    The evidence is the text around the match, not the start of the line,
    since a minified bundle is one line.

    Returns:
        List of DOM sink finding dicts
    """
    findings = []
    lines = content.split('\n')
    seen = set()
    vendor = is_vendor_js_url(source_url)
    offset = 0

    for line_num, line in enumerate(lines, 1):
        try:
            for pattern, sink_type, severity, description in DOM_SINK_PATTERNS:
                # Deduplicate by sink type + source file + line
                key = f"{sink_type}:{source_url}:{line_num}"
                if key in seen:
                    continue
                match, source = _pick_sink_match(pattern, sink_type, line, offset, content)
                if match is None:
                    continue
                seen.add(key)

                if vendor:
                    final_severity, confidence = 'info', 'low'
                    note = 'in a library/runtime file'
                elif source:
                    final_severity, confidence = severity, 'medium'
                    note = f'user-controlled source nearby: {source}'
                else:
                    final_severity = min(severity, 'low', key=_SEVERITY_RANK.__getitem__)
                    confidence = 'low'
                    note = 'no user-controlled source nearby'

                finding_id = hashlib.sha256(f"sink:{key}".encode()).hexdigest()[:16]
                findings.append({
                    'id': finding_id,
                    'finding_type': 'dom_sink',
                    'type': sink_type,
                    'pattern': _evidence_window(line, match.start(), match.end()),
                    'description': f"{description} ({note})",
                    'source_url': source_url,
                    'line': line_num,
                    'column': match.start() + 1,
                    'severity': final_severity,
                    'confidence': confidence,
                    'nominal_severity': severity,
                    'user_source': source,
                    'vendor': vendor,
                })
        except Exception as e:
            print(f"[!][JsRecon] DOM sink detection failed at line {line_num} in {source_url}: {e}")
        offset += len(line) + 1

    return findings


def detect_dev_comments(content: str, source_url: str) -> list:
    """
    Extract developer comments with TODO/FIXME/HACK markers and sensitive keywords.

    Delegates to patterns.scan_dev_comments() for consistency.
    Import is deferred to avoid circular import at module load time.
    """
    try:
        from recon.helpers.js_recon.patterns import scan_dev_comments
        return scan_dev_comments(content, source_url)
    except ImportError:
        # Fallback: import failed (e.g., running standalone)
        from .patterns import scan_dev_comments as _scan
        return _scan(content, source_url)


def load_custom_frameworks(file_path: str) -> list:
    """
    Load custom framework signatures from a user-uploaded JSON file.

    JSON format:
    [
        {
            "name": "MyFramework",
            "patterns": ["myframework\\.init", "__MY_FRAMEWORK__"],
            "version_regex": "MyFramework\\.version\\s*=\\s*[\"']([0-9.]+)[\"']"
        }
    ]
    """
    if not file_path:
        return []

    try:
        with open(file_path, 'r') as f:
            data = json.loads(f.read())
        if isinstance(data, list):
            return data
    except Exception as e:
        print(f"[!][JsRecon] Failed to load custom frameworks from {file_path}: {e}")

    return []

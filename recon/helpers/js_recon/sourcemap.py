"""
JS Recon Source Map Discovery + Analysis

Discovers .map source map files for JS files and analyzes them
to extract original source code, file paths, and embedded secrets.
"""

import re
import json
import hashlib
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import Optional

try:
    from recon.main_recon_modules.ip_filter import is_url_safe_to_probe
except ImportError:  # spawned-container path where CWD is on sys.path
    from ip_filter import is_url_safe_to_probe


# Default paths to probe for source maps
DEFAULT_SOURCEMAP_PROBE_PATHS = [
    '{url}.map',
    '{base}/static/js/{filename}.map',
    '{base}/assets/js/{filename}.map',
    '{base}/dist/{filename}.map',
    '{base}/build/{filename}.map',
    '{base}/dist/js/{filename}.map',
    '{base}/build/js/{filename}.map',
    '{base}/public/js/{filename}.map',
]


_REFERENCE_WORTH_REPORTING = frozenset({'http_401', 'http_403'})
_REFERENCE_WORTH_REPORTING_ELSEWHERE = frozenset({'unsafe', 'unreachable'})


def check_sourcemap_comment(content: str) -> Optional[str]:
    """
    Check last lines of JS content for sourceMappingURL comment.

    Returns the source map URL/path if found, None otherwise.
    """
    lines = content.strip().split('\n')
    # Check last 5 lines (source map comment is typically the very last line)
    for line in reversed(lines[-5:]):
        line = line.strip()
        match = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', line)
        if match:
            return match.group(1)
        # Also check multi-line comment style
        match = re.search(r'/\*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*\*/', line)
        if match:
            return match.group(1)
    return None


def check_sourcemap_header(headers: dict) -> Optional[str]:
    """
    Check HTTP response headers for SourceMap or X-SourceMap header.

    Returns the source map URL if found, None otherwise.
    """
    for header_name in ('SourceMap', 'X-SourceMap', 'sourcemap', 'x-sourcemap'):
        value = headers.get(header_name)
        if value:
            return value.strip()
    return None


def _resolve_map_url(js_url: str, map_ref: str) -> str:
    """Resolve a source map reference (could be relative) against the JS file URL."""
    if map_ref.startswith(('http://', 'https://', '//')):
        return map_ref
    if map_ref.startswith('data:'):
        return map_ref  # Inline source map
    return urljoin(js_url, map_ref)


def _build_probe_urls(js_url: str, custom_paths: Optional[list] = None) -> list:
    """Build list of URLs to probe for source map files."""
    parsed = urlparse(js_url)
    filename = parsed.path.split('/')[-1]
    base = f"{parsed.scheme}://{parsed.netloc}"

    paths = list(DEFAULT_SOURCEMAP_PROBE_PATHS)
    if custom_paths:
        paths.extend(custom_paths)

    urls = []
    for path_template in paths:
        try:
            url = path_template.format(
                url=js_url,
                base=base,
                filename=filename,
            )
        except (KeyError, IndexError):
            continue
        if url not in urls:
            urls.append(url)

    return urls


def _is_valid_sourcemap(data) -> bool:
    """A Source Map v3: `version` 3 with `sources` + string `mappings`, or an
    index map with `sections`. A JSON API catch-all (`{"error": ...}`) or a
    manifest that merely lists `sources` is not one."""
    if not isinstance(data, dict) or str(data.get('version')) != '3':
        return False
    if isinstance(data.get('sections'), list):
        return True
    return isinstance(data.get('sources'), list) and isinstance(data.get('mappings'), str)


# Anti-JSON-hijacking prefix some servers put in front of JSON bodies.
_XSSI_PREFIX = re.compile(r"^\s*\)\]\}'?[^\n]*\n?")


def _parse_sourcemap_body(text: str, outcome: dict) -> Optional[dict]:
    text = text.lstrip('\ufeff')
    if text.lstrip().startswith('<'):
        outcome['reason'] = 'html'
        return None
    try:
        data = json.loads(_XSSI_PREFIX.sub('', text, count=1))
    except ValueError:
        outcome['reason'] = 'not_json'
        return None
    if not _is_valid_sourcemap(data):
        outcome['reason'] = 'invalid_schema'
        return None
    outcome['reason'] = 'ok'
    return data


def _fetch_sourcemap(url: str, timeout: int = 10, outcome: Optional[dict] = None) -> Optional[dict]:
    """Fetch and parse a source map JSON file. Uses HEAD to skip guaranteed misses.

    `outcome`, when given, receives `reason` (and `status` for an HTTP
    answer): ok, html, not_json, invalid_schema, not_found, unreachable,
    unsafe or http_<status>. A single-page app answers every unknown path,
    `.map` included, with its HTML shell and a 200, so a 200 alone proves
    nothing: the body must parse as a v3 source map.
    """
    outcome = outcome if outcome is not None else {}
    if url.startswith('data:'):
        # Inline base64-encoded source map
        try:
            import base64
            _, data = url.split(',', 1)
            content = base64.b64decode(data).decode('utf-8')
        except Exception:
            outcome['reason'] = 'not_json'
            return None
        return _parse_sourcemap_body(content, outcome)

    # STRIDE I14: source-map URLs are derived from target JS; refuse to fetch
    # ones that resolve to cloud metadata / loopback / an internal host.
    if not is_url_safe_to_probe(url):
        outcome['reason'] = 'unsafe'
        return None

    headers = {'User-Agent': 'Mozilla/5.0'}
    head_timeout = min(timeout, 5)

    try:
        head = requests.head(url, timeout=head_timeout, allow_redirects=True, headers=headers)
        # Skip definite misses without paying for a body download. Other statuses
        # (200, 403, 405, 5xx) fall through to GET — some servers misreport HEAD.
        if head.status_code in (404, 410):
            outcome.update(reason='not_found', status=head.status_code)
            return None
    except requests.RequestException:
        # Connection-level failure on HEAD: GET would fail too.
        outcome['reason'] = 'unreachable'
        return None

    try:
        resp = requests.get(url, timeout=timeout, headers=headers)
    except requests.RequestException:
        outcome['reason'] = 'unreachable'
        return None
    outcome['status'] = resp.status_code
    if resp.status_code in (404, 410):
        outcome['reason'] = 'not_found'
        return None
    if resp.status_code != 200:
        outcome['reason'] = f'http_{resp.status_code}'
        return None
    # Any content type: S3 and CDNs serve maps as octet-stream, and the body
    # check rejects an HTML page whatever it is labelled. The bytes are decoded
    # directly, so a multi-MB map skips charset sniffing.
    try:
        raw = resp.content
        text = raw.decode('utf-8', 'replace') if isinstance(raw, (bytes, bytearray)) else (resp.text or '')
        return _parse_sourcemap_body(text, outcome)
    except Exception:
        outcome['reason'] = 'not_json'
        return None


# Package-manager and bundler-runtime sources: library code the target ships
# but did not write. Matched after the `webpack:///`-style scheme is removed.
_VENDOR_SOURCE_RE = re.compile(
    r'(?:^|/)(?:node_modules|bower_components|jspm_packages)/'
    # Unanchored: Next.js prefixes its own runtime (`webpack://_N_E/webpack/runtime/...`).
    r'|(?:^|/)webpack/(?:bootstrap|runtime|universalModuleDefinition)'
    r'|\(webpack\)|^external[ "]|^~/',
    re.IGNORECASE,
)
_SOURCE_SCHEME = re.compile(r'^[a-z][a-z0-9+.-]*:/*', re.IGNORECASE)


def _is_vendor_source(source: str) -> bool:
    path = _SOURCE_SCHEME.sub('', source or '').lstrip('./')
    return bool(_VENDOR_SOURCE_RE.search(path)) or bool(_VENDOR_SOURCE_RE.search(source or ''))


def _map_sources(map_data: dict) -> tuple:
    """(sources, sourcesContent) of a flat map, or of every inline section of
    an index map."""
    # A null source keeps its slot (as ""): sourcesContent pairs by index.
    def flat(m: dict) -> tuple:
        s = [x if isinstance(x, str) else '' for x in (m.get('sources') or [])]
        c = list(m.get('sourcesContent') or [])
        return s, c + [None] * (len(s) - len(c))

    if isinstance(map_data.get('sections'), list):
        sources, contents = [], []
        for section in map_data['sections']:
            inner = (section or {}).get('map') if isinstance(section, dict) else None
            if isinstance(inner, dict):
                s, c = flat(inner)
                sources.extend(s)
                contents.extend(c[:len(s)])
        return sources, contents
    return flat(map_data)


def analyze_sourcemap(
    map_data: dict,
    map_url: str,
    js_url: str,
    scan_content_func=None,
) -> dict:
    """
    Analyze a parsed source map.

    Args:
        map_data: Parsed source map JSON
        map_url: URL of the source map
        js_url: URL of the original JS file
        scan_content_func: Optional function(content, source_url) -> list to scan source content

    Severity follows what the map discloses about the target's own code:
    high when it embeds first-party source text, medium for first-party file
    paths only, low when every source is a library (node_modules, the
    bundler runtime), which is public code.

    Returns:
        dict with: js_url, map_url, sources, source_count, secrets_in_source, file_paths
    """
    sources, sources_content = _map_sources(map_data)
    first_party = [i for i, s in enumerate(sources) if s and not _is_vendor_source(s)]
    first_party_content = any(
        isinstance(sources_content[i], str) and sources_content[i].strip()
        for i in first_party if i < len(sources_content)
    )
    if first_party_content:
        severity = 'high'
    elif first_party:
        severity = 'medium'
    else:
        severity = 'low'

    finding_id = hashlib.sha256(f"srcmap:{js_url}:{map_url}".encode()).hexdigest()[:16]
    result = {
        'id': finding_id,
        'js_url': js_url,
        'map_url': map_url,
        'accessible': True,
        'discovery_method': 'probe',
        'files_count': len([x for x in sources if x]),
        'first_party_files': len(first_party),
        'has_sources_content': first_party_content,
        'source_files': [sources[i] for i in first_party][:100] or [x for x in sources if x][:100],
        'secrets_in_source': 0,
        'secrets': [],
        'severity': severity,
        'finding_type': 'source_map_exposure',
    }

    # If sourcesContent is available, scan the target's own files for secrets;
    # a library's bundled source is public and full of example keys.
    if sources_content and scan_content_func:
        own = set(first_party)
        for i, content in enumerate(sources_content):
            if not content or not isinstance(content, str) or i not in own:
                continue
            source_name = sources[i] if i < len(sources) else f"source_{i}"
            findings = scan_content_func(content, f"{map_url}:{source_name}")
            if findings:
                result['secrets_in_source'] += len(findings)
                result['secrets'].extend(findings[:20])  # Cap per source file

    return result


def discover_and_analyze_sourcemaps(
    js_files: list,
    settings: dict,
    scan_content_func=None,
) -> list:
    """
    Discover and analyze source maps for a list of JS files.

    Args:
        js_files: List of dicts with 'url', 'content', and optionally 'headers'
        settings: Project settings dict
        scan_content_func: Function to scan source content for secrets

    Returns:
        List of source map finding dicts
    """
    if not settings.get('JS_RECON_SOURCE_MAPS', True):
        return []

    # Load custom probe paths
    custom_paths = []
    custom_file = settings.get('JS_RECON_CUSTOM_SOURCEMAP_PATHS', '')
    if custom_file:
        try:
            with open(custom_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        custom_paths.append(line)
        except Exception as e:
            print(f"[!][JsRecon] Failed to load custom sourcemap paths: {e}")

    checked_map_urls = set()
    checked_lock = threading.Lock()
    # Use fraction of overall timeout for each sourcemap fetch, minimum 10s
    timeout = max(settings.get('JS_RECON_TIMEOUT', 900) // 60, 10)

    def _claim(url: str) -> bool:
        """Atomically reserve a probe URL. Returns False if already claimed."""
        with checked_lock:
            if url in checked_map_urls:
                return False
            checked_map_urls.add(url)
            return True

    def _process(js_file: dict) -> list:
        try:
            js_url = js_file.get('url', '')
            content = js_file.get('content', '')
            headers = js_file.get('headers', {})

            if not js_url:
                return []

            # Skip a host already known unreachable this run: otherwise each JS
            # file costs up to 8 guessed .map probes (HEAD+GET) against a dead
            # host. is_down is inert under the off switch. (HostHealth,
            # recon/helpers/circuit_breaker.py)
            try:
                from recon.helpers import circuit_breaker as _cb
                if _cb.host_health.is_down(js_url):
                    return []
            except Exception:  # noqa: BLE001 - a fault here scans as today
                pass

            map_url = None
            discovery_method = None

            # Method 1: Check sourceMappingURL comment in JS content
            map_ref = check_sourcemap_comment(content)
            if map_ref:
                map_url = _resolve_map_url(js_url, map_ref)
                discovery_method = 'comment'

            # Method 2: Check HTTP response headers
            if not map_url:
                header_ref = check_sourcemap_header(headers)
                if header_ref:
                    map_url = _resolve_map_url(js_url, header_ref)
                    discovery_method = 'header'

            # Method 3: Probe common paths
            if not map_url:
                for probe_url in _build_probe_urls(js_url, custom_paths):
                    if not _claim(probe_url):
                        continue
                    map_data = _fetch_sourcemap(probe_url, timeout=timeout)
                    if map_data:
                        result = analyze_sourcemap(map_data, probe_url, js_url, scan_content_func)
                        result['discovery_method'] = 'probe'
                        return [result]
                return []

            # Fetch and analyze the discovered source map
            if not _claim(map_url):
                return []
            outcome: dict = {}
            map_data = _fetch_sourcemap(map_url, timeout=timeout, outcome=outcome)
            if map_data:
                result = analyze_sourcemap(map_data, map_url, js_url, scan_content_func)
                result['discovery_method'] = discovery_method
                return [result]
            # Referenced but not served. Only an access refusal says the map
            # exists somewhere, or a reference to ANOTHER host we could not or
            # may not reach (an internal build server leaks its name); a 404,
            # an SPA's HTML shell or a JSON error page says nothing, and
            # reporting those buried the board in rows.
            reason = outcome.get('reason')
            other_host = urlparse(map_url).hostname not in (None, urlparse(js_url).hostname)
            if reason not in _REFERENCE_WORTH_REPORTING and not (
                    other_host and reason in _REFERENCE_WORTH_REPORTING_ELSEWHERE):
                return []
            finding_id = hashlib.sha256(f"srcmap-ref:{js_url}:{map_url}".encode()).hexdigest()[:16]
            return [{
                'id': finding_id,
                'js_url': js_url,
                'map_url': map_url,
                'accessible': False,
                'fetch_result': outcome['reason'],
                'discovery_method': discovery_method,
                'files_count': 0,
                'first_party_files': 0,
                'has_sources_content': False,
                'source_files': [],
                'secrets_in_source': 0,
                'secrets': [],
                'severity': 'info',
                'finding_type': 'source_map_reference',
            }]
        except Exception as e:
            print(f"[!][JsRecon] Error processing sourcemap for {js_file.get('url', '?')}: {e}")
            return []

    workers = max(1, min(settings.get('JS_RECON_CONCURRENCY', 10), 20))
    findings = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed(ex.submit(_process, jf) for jf in js_files):
            findings.extend(fut.result())

    return findings

import os
import sys
from pathlib import Path
from urllib.parse import urlencode

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.helpers import _classify_ip, allowed_hosts_for, include_root_for, root_for_host

#: A BaseURL is a thin service-identity node: httpx writes the response data
#: (status, content type, CDN flags) onto the Endpoint it probed, never onto the
#: BaseURL. Reading `b.status_code` therefore always saw null, so every partial
#: target looked like a 200 and the CDN prefilter never fired. Pick the probed
#: Endpoint: the root path first, then one httpx wrote (it alone sets `server`).
#: The `coalesce(b.x, probe.x)` readers still honour a graph from before the split.
_PROBED_ENDPOINT = """
                OPTIONAL MATCH (b)-[:HAS_ENDPOINT]->(probe:Endpoint)
                WHERE probe.status_code IS NOT NULL
                WITH b, probe
                ORDER BY CASE WHEN probe.path = '/' THEN 0
                              WHEN probe.server IS NOT NULL THEN 1 ELSE 2 END,
                         probe.path
                WITH b, head(collect(probe)) AS probe
"""

#: Rebuilds the http_probe by_url "technologies" strings the full pipeline
#: hands the CVE lookup and the Nuclei AI tag fingerprint: httpx's
#: "Name:version" (bare "Name" without one), with wappalyzer's merged in the
#: same spelling. http_mixin split each on its first ':' into Technology
#: {name, version ''|v}. Only the httpx/wappalyzer edges, since an AI-surface
#: or nmap Technology was never in that list; the 0-hop BaseURL edge is a graph
#: from before technologies moved onto the Endpoint.
_URL_TECHNOLOGIES = """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT*0..1]->(n)
                      -[r:USES_TECHNOLOGY]->(t:Technology {user_id: $uid, project_id: $pid})
                WHERE coalesce(r.detected_by, 'httpx') IN ['httpx', 'wappalyzer']
                  AND t.name IS NOT NULL AND t.name <> ''
                  AND ($urls IS NULL OR b.url IN $urls)
                WITH b.url AS url, t.name AS name, coalesce(t.version, '') AS version
                ORDER BY url, name, version
                RETURN url, collect(DISTINCT CASE WHEN version = '' THEN name
                                                  ELSE name + ':' + version END) AS technologies
"""


def _field(record, key):
    """A column a query may not return in every caller's graph, read as None when absent."""
    try:
        return record[key]
    except (KeyError, IndexError):
        return None


def _graph_url_technologies(session, user_id: str, project_id: str, urls=None) -> dict:
    """{baseurl: ["Name:version", ...]} for the BaseURLs that carry any."""
    out = {}
    for record in session.run(_URL_TECHNOLOGIES, uid=user_id, pid=project_id, urls=urls):
        url = _field(record, "url")
        techs = [t for t in (_field(record, "technologies") or []) if isinstance(t, str) and t]
        if isinstance(url, str) and techs:
            out[url] = techs
    return out


def _graph_nmap_services(session, user_id: str, project_id: str, ips: list) -> list:
    """nmap -sV product/version on this run's IPs, shaped like nmap_scan.services_detected."""
    if not ips:
        return []
    result = session.run(
        """
        MATCH (p:Port {user_id: $uid, project_id: $pid})
        WHERE p.ip_address IN $ips
          AND p.product IS NOT NULL AND p.product <> ''
          AND p.version IS NOT NULL AND p.version <> ''
        RETURN p.ip_address AS ip, p.number AS port, p.product AS product,
               p.version AS version, p.cpe AS cpe
        ORDER BY ip, port
        """,
        ips=ips, uid=user_id, pid=project_id,
    )
    services = []
    for record in result:
        product, version = _field(record, "product"), _field(record, "version")
        if isinstance(product, str) and isinstance(version, str) and product and version:
            services.append({"product": product, "version": version,
                             "port": _field(record, "port"), "host": _field(record, "ip"),
                             "cpe": _field(record, "cpe") or ""})
    return services


def graph_url_fingerprints(base_urls, user_id: str, project_id: str) -> dict:
    """{baseurl: {"technologies": [...], "server": str|None}} from the graph. Never raises.

    For URLs a user typed into partial Nuclei: without the BaseURL's
    fingerprint they reach the CVE lookup and the AI tag selector empty.
    """
    urls = sorted({u for u in (base_urls or []) if isinstance(u, str) and u})
    if not urls:
        return {}
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                return {}
            with graph_client.driver.session() as session:
                out = {}
                result = session.run(
                    """
                    MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                    WHERE b.url IN $urls
                    """ + _PROBED_ENDPOINT + """
                    RETURN b.url AS url, coalesce(b.server, probe.server) AS server
                    """,
                    urls=urls, uid=user_id, pid=project_id,
                )
                for record in result:
                    url = _field(record, "url")
                    if isinstance(url, str):
                        out.setdefault(url, {"technologies": [], "server": None})["server"] = (
                            _field(record, "server"))
                for url, techs in _graph_url_technologies(session, user_id, project_id,
                                                          urls=urls).items():
                    out.setdefault(url, {"technologies": [], "server": None})["technologies"] = techs
                return out
    except Exception as e:
        print(f"[!][Partial Recon] Could not read technologies for user URLs: {e}")
        return {}


def graph_open_ports(ips, user_id: str, project_id: str) -> dict:
    """{ip: [open port numbers]} from the graph's Port nodes. Never raises.

    The port/service security checks read open ports from port_scan.by_ip,
    which the vuln-scan builder fills with CDN metadata only.
    """
    ips = sorted({ip for ip in (ips or []) if isinstance(ip, str) and ip})
    if not ips:
        return {}
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                return {}
            with graph_client.driver.session() as session:
                result = session.run(
                    """
                    MATCH (p:Port {user_id: $uid, project_id: $pid})
                    WHERE p.ip_address IN $ips AND p.number IS NOT NULL
                      AND coalesce(p.state, 'open') = 'open'
                    RETURN p.ip_address AS ip, collect(DISTINCT p.number) AS ports
                    """,
                    ips=ips, uid=user_id, pid=project_id,
                )
                out = {}
                for record in result:
                    ports = sorted({int(p) for p in (_field(record, "ports") or [])
                                    if isinstance(p, int) or str(p).isdigit()})
                    if ports:
                        out[_field(record, "ip")] = ports
                return out
    except Exception as e:
        print(f"[!][Partial Recon] Could not read open ports for the port checks: {e}")
        return {}


def _as_roots(domains) -> list:
    """A builder's roots: a list, or one root from a caller not yet migrated."""
    if isinstance(domains, str):
        return [domains] if domains else []
    return [d for d in (domains or []) if isinstance(d, str) and d]


def _root_scope(roots: list, domain_groups, include_root_domain: bool):
    """Which roots' apexes are targets, and each literal root's allowed hosts.

    With domain_groups (the scope partial_recon.main built from settings), each
    root follows its own group. Without them, a caller not yet migrated gets
    the single include_root_domain flag and no host narrowing, as before.
    Returns (apex_roots, {root: allowed_host_set}).
    """
    if domain_groups is None:
        return (list(roots) if include_root_domain else []), {}
    apex_roots = [r for r in roots if include_root_for(r, domain_groups)]
    allowed = {}
    for root in roots:
        hosts = allowed_hosts_for(root, domain_groups)
        if hosts is not None:
            allowed[root] = hosts
    return apex_roots, allowed


def _host_allowed(root: str, host: str, allowed: dict) -> bool:
    """A literal batch group scans exactly its listed hosts; anything else passes."""
    hosts = allowed.get(root)
    return hosts is None or (host or "").strip().lower() in hosts


def _other_domains(session, user_id: str, project_id: str, roots: list) -> list:
    """The project's Domain nodes this run does not cover.

    A root removed from the batch keeps its node (and its hosts' BaseURLs)
    until the next full recon clears the graph, and the operator may have left
    a current root unticked. BaseURLs are read project-wide, so without this
    their hosts would still be scanned.
    """
    wanted = {r.lower() for r in roots}
    result = session.run(
        "MATCH (d:Domain {user_id: $uid, project_id: $pid}) RETURN d.name AS name",
        uid=user_id, pid=project_id,
    )
    return [r["name"] for r in result if r["name"] and r["name"].lower() not in wanted]


def _co_hosted_vhost_hosts(session, user_id: str, project_id: str) -> frozenset:
    """Hostnames the graph knows only as a co-hosted third party's virtual host.

    VHost/SNI enumeration keeps a BaseURL for a name it found on a target IP
    even when the name is outside the engagement (hung off the Service, owned by
    no Subdomain). That is a record of what the IP serves, not a target: the
    name resolves wherever its own DNS says, usually a third party's server.
    A host some other writer also recorded is left alone. Never raises; on a
    failed read nothing extra is dropped.
    """
    try:
        result = session.run(
            """
            MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
            WHERE b.discovery_source = 'vhost_sni_enum' AND b.host IS NOT NULL
              AND NOT EXISTS { MATCH (b)<-[:HAS_BASE_URL]-(:Subdomain) }
            WITH DISTINCT toLower(b.host) AS host
            WHERE NOT EXISTS {
                MATCH (o:BaseURL {user_id: $uid, project_id: $pid})
                WHERE toLower(o.host) = host
                  AND coalesce(o.discovery_source, '') <> 'vhost_sni_enum'
            }
            RETURN collect(host) AS co_hosted_vhost_hosts
            """,
            uid=user_id, pid=project_id,
        )
        hosts = set()
        for record in result:
            hosts.update(h for h in (record.get("co_hosted_vhost_hosts") or []) if h)
        return frozenset(hosts)
    except Exception:  # noqa: BLE001
        return frozenset()


def graph_url_scope(session, user_id: str, project_id: str, domains, domain_groups,
                    include_root_domain: bool = False, apex_filter: bool = True):
    """A predicate over a graph URL's host: is it a target of this run?

    Drops a host under a Domain this run does not cover, and a host a literal
    batch group never listed. With apex_filter, also an apex its group
    excludes (the tools that always honoured Include Root Domain). A host under
    no project root (an IP, a third-party host) is kept, as before, unless the
    graph knows it only as a co-hosted vhost name (_co_hosted_vhost_hosts). A caller
    not yet migrated (no domain_groups) gets only the apex rule it had.
    """
    roots = _as_roots(domains)
    apex_roots, allowed = _root_scope(roots, domain_groups, include_root_domain)
    other_roots = _other_domains(session, user_id, project_id, roots) if domain_groups is not None else []
    known = roots + other_roots
    # Loaded lazily, and only when a host under no project root turns up: the
    # common run has none, so the extra query never fires (and fixed-sequence
    # test mocks are untouched).
    co_hosted_cache: dict = {}

    def _co_hosted() -> frozenset:
        if "set" not in co_hosted_cache:
            co_hosted_cache["set"] = _co_hosted_vhost_hosts(session, user_id, project_id)
        return co_hosted_cache["set"]

    def keep(host) -> bool:
        host = (host or "").strip().lower()
        if not host:
            return True
        root = root_for_host(host, known)
        if root is None:
            return host not in _co_hosted()
        if root in other_roots:
            return False
        if apex_filter and host == root.lower() and root not in apex_roots:
            return False
        return _host_allowed(root, host, allowed)

    return keep


def url_host(url: str, host: str = "") -> str:
    """A BaseURL's host: its stored `host`, else parsed from the URL (older nodes lack it)."""
    if host:
        return host.lower()
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def graph_target_hosts(user_id: str, project_id: str, domains, domain_groups,
                       include_root_domain: bool = False, include_graph: bool = True) -> list:
    """The in-scope hosts to hand a passive URL source (Gau, ParamSpider) for a
    whole run.

    Each root's apex is a target when its group includes it (always for a
    wildcard or single-domain root, matching today's single-root behaviour),
    plus every Subdomain under the run's roots, dropping the hosts a literal
    group never listed. With the graph unreachable, only the apexes are
    returned. A caller not yet migrated (a single string) keeps its one root.
    """
    from graph_db import Neo4jClient

    roots = _as_roots(domains)
    _apex_roots, allowed = _root_scope(roots, domain_groups, include_root_domain)
    hosts = set()
    for root in roots:
        # A wildcard/single root has no allowed set: its apex is always a target,
        # as today. A literal group lists its apex only when it wrote ".".
        if root not in allowed or root.lower() in allowed[root]:
            hosts.add(root)
    if not include_graph or not roots:
        return sorted(hosts)

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph subdomains")
            return sorted(hosts)
        with graph_client.driver.session() as session:
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})-[:HAS_SUBDOMAIN]->(s:Subdomain)
                WHERE d.name IN $domains
                RETURN d.name AS root, s.name AS sub
                """,
                domains=roots, uid=user_id, pid=project_id,
            )
            for record in result:
                if _host_allowed(record["root"], record["sub"], allowed):
                    hosts.add(record["sub"])
    return sorted(hosts)


def _build_recon_data_from_graph(domains, user_id: str, project_id: str,
                                 include_root_domain: bool = False,
                                 domain_groups: list = None) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_port_scan expects.

    Returns a dict with 'domain' and 'dns' keys matching the structure
    produced by domain_recon.py (domain IPs + subdomain IPs).

    `domains` is the run's roots (or one root from a caller not yet migrated),
    scoped per root as in _build_port_scan_data_from_graph: an apex is loaded
    only when its group includes it, and a literal batch group only its listed
    hosts. The first root's apex fills dns.domain and another root's apex is a
    host under dns.subdomains. metadata.include_root_domain describes the first
    root, so extract_targets_from_recon adds that apex only when in scope.
    """
    from graph_db import Neo4jClient

    roots = _as_roots(domains)
    apex_roots, allowed = _root_scope(roots, domain_groups, include_root_domain)
    primary = roots[0] if roots else ""

    recon_data = {
        "domain": primary,
        "domains": roots,
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
        "metadata": {"include_root_domain": primary in apex_roots},
    }
    if not roots:
        return recon_data

    def _add_ip(ips: dict, addr: str, version) -> None:
        bucket = _classify_ip(addr, version)
        if addr not in ips[bucket]:
            ips[bucket].append(addr)

    def _dns_entry(host: str) -> dict:
        return recon_data["dns"]["subdomains"].setdefault(
            host, {"ips": {"ipv4": [], "ipv6": []}, "has_records": True})

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            if apex_roots:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})-[:RESOLVES_TO]->(i:IP)
                    WHERE d.name IN $apex_roots
                    RETURN d.name AS root, i.address AS address, i.version AS version
                    """,
                    apex_roots=apex_roots, uid=user_id, pid=project_id,
                )
                for record in result:
                    if record["root"] == primary:
                        _add_ip(recon_data["dns"]["domain"]["ips"], record["address"], record["version"])
                        recon_data["dns"]["domain"]["has_records"] = True
                    else:
                        _add_ip(_dns_entry(record["root"])["ips"], record["address"], record["version"])

            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                      -[:RESOLVES_TO]->(i:IP)
                WHERE d.name IN $domains
                RETURN d.name AS root, s.name AS subdomain, i.address AS address, i.version AS version
                """,
                domains=roots, uid=user_id, pid=project_id,
            )
            for record in result:
                if not _host_allowed(record["root"], record["subdomain"], allowed):
                    continue
                _add_ip(_dns_entry(record["subdomain"])["ips"], record["address"], record["version"])

    return recon_data


def _build_port_scan_data_from_graph(domains, user_id: str, project_id: str,
                                     include_root_domain: bool = False,
                                     domain_groups: list = None) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_nmap_scan expects.

    Returns a dict with 'port_scan' key containing by_ip, by_host, and
    ip_to_hostnames structures matching what build_nmap_targets() consumes.
    Also populates a 'dns' section for user-IP linking logic.

    `domains` is the run's roots (or one root from a caller not yet migrated).
    Each root's apex is a target only when its group includes it, and a literal
    batch group loads only its listed hosts, not every Subdomain a writer has
    since hung under the root (certificate SANs, urlscan). The first root's apex
    fills dns.domain; another root's apex is recorded as a host under
    dns.subdomains, the one place extract_targets_from_recon reads a second
    apex from. metadata.include_root_domain describes the first root.
    """
    from graph_db import Neo4jClient

    roots = _as_roots(domains)
    apex_roots, allowed = _root_scope(roots, domain_groups, include_root_domain)
    primary = roots[0] if roots else ""

    recon_data = {
        "domain": primary,
        "domains": roots,
        "port_scan": {
            "by_ip": {},
            "by_host": {},
            "ip_to_hostnames": {},
            "all_ports": [],
            "scan_metadata": {"scanners": ["naabu"]},
            "summary": {},
        },
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
        "metadata": {"include_root_domain": primary in apex_roots},
    }

    all_ports_set = set()

    def _add_host(host: str, ip_addr: str, port_numbers: list, port_details: list) -> None:
        """Record one host -> IP -> ports row in by_ip, by_host and ip_to_hostnames."""
        if ip_addr not in recon_data["port_scan"]["by_ip"]:
            recon_data["port_scan"]["by_ip"][ip_addr] = {
                "ip": ip_addr,
                "hostnames": [host],
                "ports": list(port_numbers),
                "port_details": list(port_details),
            }
        else:
            existing = recon_data["port_scan"]["by_ip"][ip_addr]
            if host not in existing["hostnames"]:
                existing["hostnames"].append(host)
            for pnum in port_numbers:
                if pnum not in existing["ports"]:
                    existing["ports"].append(pnum)
            for pd in port_details:
                if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                    existing["port_details"].append(pd)

        if host not in recon_data["port_scan"]["by_host"]:
            recon_data["port_scan"]["by_host"][host] = {
                "host": host,
                "ip": ip_addr,
                "ports": list(port_numbers),
                "port_details": list(port_details),
            }
        else:
            existing = recon_data["port_scan"]["by_host"][host]
            for pnum in port_numbers:
                if pnum not in existing["ports"]:
                    existing["ports"].append(pnum)
            for pd in port_details:
                if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                    existing["port_details"].append(pd)

        recon_data["port_scan"]["ip_to_hostnames"].setdefault(ip_addr, [])
        if host not in recon_data["port_scan"]["ip_to_hostnames"][ip_addr]:
            recon_data["port_scan"]["ip_to_hostnames"][ip_addr].append(host)

    def _ports(ports_data) -> tuple:
        # OPTIONAL MATCH yields one null-port map when an IP has no ports.
        numbers, details = [], []
        for p in ports_data:
            if p["number"] is not None:
                pnum = int(p["number"])
                numbers.append(pnum)
                all_ports_set.add(pnum)
                details.append({"port": pnum, "protocol": p["protocol"] or "tcp", "service": ""})
        return numbers, details

    def _dns_entry(host: str) -> dict:
        return recon_data["dns"]["subdomains"].setdefault(
            host, {"ips": {"ipv4": [], "ipv6": []}, "has_records": True})

    if not roots:
        return recon_data

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # Apex Domain -> IP -> Port, only for the roots whose scope includes it.
            apex_records = []
            if apex_roots:
                apex_records = list(session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})-[:RESOLVES_TO]->(i:IP)
                    WHERE d.name IN $apex_roots
                    OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
                    RETURN d.name AS root, i.address AS ip, i.version AS version,
                           collect(DISTINCT {number: p.number, protocol: p.protocol}) AS ports
                    """,
                    apex_roots=apex_roots, uid=user_id, pid=project_id,
                ))
            for record in apex_records:
                root = record["root"]
                ip_addr = record["ip"]
                bucket = _classify_ip(ip_addr, record["version"])
                if root == primary:
                    if ip_addr not in recon_data["dns"]["domain"]["ips"][bucket]:
                        recon_data["dns"]["domain"]["ips"][bucket].append(ip_addr)
                        recon_data["dns"]["domain"]["has_records"] = True
                else:
                    ips = _dns_entry(root)["ips"][bucket]
                    if ip_addr not in ips:
                        ips.append(ip_addr)
                port_numbers, port_details = _ports(record["ports"])
                _add_host(root, ip_addr, port_numbers, port_details)

            # Subdomain -> IP -> Port relationships
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
                WHERE d.name IN $domains
                OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
                RETURN d.name AS root, s.name AS subdomain, i.address AS ip, i.version AS version,
                       collect(DISTINCT {number: p.number, protocol: p.protocol}) AS ports
                """,
                domains=roots, uid=user_id, pid=project_id,
            )
            for record in result:
                subdomain = record["subdomain"]
                if not _host_allowed(record["root"], subdomain, allowed):
                    continue
                ip_addr = record["ip"]
                bucket = _classify_ip(ip_addr, record["version"])
                sub_ips = _dns_entry(subdomain)["ips"]
                if ip_addr not in sub_ips[bucket]:
                    sub_ips[bucket].append(ip_addr)
                port_numbers, port_details = _ports(record["ports"])
                _add_host(subdomain, ip_addr, port_numbers, port_details)

    recon_data["port_scan"]["all_ports"] = sorted(all_ports_set)
    return recon_data


def _build_http_probe_data_from_graph(domains, user_id: str, project_id: str,
                                      include_root_domain: bool = False,
                                      domain_groups: list = None) -> dict:
    """
    Query Neo4j to build the recon_data dict for crawlers/fuzzers running in
    partial recon (Katana, Hakrawler, FFuf, Kiterunner).

    Populates:
      - 'http_probe.by_url': BaseURL nodes (Source 2 of build_target_urls)
      - 'dns.domain': the first root's apex IPs (Source 3 fallback), only when
        its group includes the apex; another root's apex is a dns.subdomains host
      - 'dns.subdomains': every Subdomain with its IPs + has_records
      - 'subdomains': flat list for scope filtering in graph updates
      - 'metadata.include_root_domain': stamped so extract_targets_from_recon
        excludes the first root's apex when scope says so.

    `domains` is the run's roots, scoped per root like the other builders.
    BaseURLs are read project-wide and then filtered by graph_url_scope: an
    excluded apex, a host a literal group never listed, and a host under a
    Domain this run does not cover are all dropped.
    """
    from graph_db import Neo4jClient

    roots = _as_roots(domains)
    apex_roots, allowed = _root_scope(roots, domain_groups, include_root_domain)
    primary = roots[0] if roots else ""

    recon_data = {
        "domain": primary,
        "domains": roots,
        "subdomains": [],
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
        "http_probe": {
            "by_url": {},
        },
        "metadata": {"include_root_domain": primary in apex_roots},
    }
    if not roots:
        return recon_data

    def _add_ip(ips: dict, addr: str, version) -> None:
        bucket = _classify_ip(addr, version)
        if addr not in ips[bucket]:
            ips[bucket].append(addr)

    def _dns_entry(host: str) -> dict:
        return recon_data["dns"]["subdomains"].setdefault(
            host, {"ips": {"ipv4": [], "ipv6": []}, "has_records": True})

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # 1) Apex Domain -> IP (Source 3 fallback), only for included apexes.
            if apex_roots:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})-[:RESOLVES_TO]->(i:IP)
                    WHERE d.name IN $apex_roots
                    RETURN d.name AS root, i.address AS address, i.version AS version
                    """,
                    apex_roots=apex_roots, uid=user_id, pid=project_id,
                )
                for record in result:
                    if record["root"] == primary:
                        _add_ip(recon_data["dns"]["domain"]["ips"], record["address"], record["version"])
                        recon_data["dns"]["domain"]["has_records"] = True
                    else:
                        _add_ip(_dns_entry(record["root"])["ips"], record["address"], record["version"])

            # 2) Subdomain -> IP relationships (Source 3 fallback for unprobed subs)
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                      -[:RESOLVES_TO]->(i:IP)
                WHERE d.name IN $domains
                RETURN d.name AS root, s.name AS subdomain, i.address AS address, i.version AS version
                """,
                domains=roots, uid=user_id, pid=project_id,
            )
            for record in result:
                if not _host_allowed(record["root"], record["subdomain"], allowed):
                    continue
                _add_ip(_dns_entry(record["subdomain"])["ips"], record["address"], record["version"])

            # 3) BaseURL nodes (Source 2: live URLs verified by httpx)
            keep = graph_url_scope(session, user_id, project_id, roots, domain_groups,
                                   include_root_domain=include_root_domain)
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                """ + _PROBED_ENDPOINT + """
                RETURN b.url AS url, coalesce(b.status_code, probe.status_code) AS status_code,
                       b.host AS host, coalesce(b.content_type, probe.content_type) AS content_type
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                status_code = record["status_code"]
                # Skip URLs with server errors (same filter as resource_enum)
                if status_code is not None and int(status_code) >= 500:
                    continue
                if not keep(url_host(url, record["host"] or "")):
                    continue
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": record["host"] or "",
                    "status_code": int(status_code) if status_code is not None else 200,
                    "content_type": record["content_type"] or "",
                }

            # 4) Flat subdomain list for graph-update scope filtering
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                WHERE d.name IN $domains
                RETURN collect(DISTINCT s.name) AS subdomains
                """,
                domains=roots, uid=user_id, pid=project_id,
            )
            record = result.single()
            if record:
                recon_data["subdomains"] = [
                    sub for sub in record["subdomains"] or []
                    if _host_allowed(root_for_host(sub, roots), sub, allowed)
                ]

    return recon_data


def _build_vuln_scan_data_from_graph(domains, user_id: str, project_id: str,
                                     include_root_domain: bool = False,
                                     domain_groups: list = None) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_vuln_scan expects.

    Returns a dict with 'domain', 'dns', 'subdomains', 'http_probe', and
    'resource_enum' keys. The vuln_scan module uses extract_targets_from_recon()
    (needs dns) and build_target_urls() (prefers resource_enum > http_probe).

    `domains` is the run's roots, scoped per root like the other builders: an
    apex only when its group includes it, a literal group's listed hosts only,
    and BaseURLs/Endpoints filtered by graph_url_scope (a host under a Domain
    this run does not cover, or an excluded apex, is dropped). The first root's
    apex fills dns.domain; another root's apex is a dns.subdomains host.
    """
    from graph_db import Neo4jClient

    roots = _as_roots(domains)
    apex_roots, allowed = _root_scope(roots, domain_groups, include_root_domain)
    primary = roots[0] if roots else ""

    recon_data = {
        "domain": primary,
        "domains": roots,
        "subdomains": [],
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
        "metadata": {"include_root_domain": primary in apex_roots},
        "http_probe": {
            "by_url": {},
        },
        "port_scan": {
            "by_ip": {},
        },
        "resource_enum": {
            "by_base_url": {},
            "discovered_urls": [],
        },
    }
    if not roots:
        return recon_data

    def _hydrate_ip_metadata(addr: str, is_cdn, cdn_name, asn) -> None:
        """Populate port_scan.by_ip with CDN/ASN metadata so collect_cdn_ips
        and collect_asn_cdn_ips can detect CDN IPs in partial-recon mode."""
        if not addr:
            return
        entry = recon_data["port_scan"]["by_ip"].setdefault(addr, {
            "ip": addr,
            "hostnames": [],
            "ports": [],
            "is_cdn": False,
            "cdn": None,
            "asn": None,
        })
        if is_cdn and not entry["is_cdn"]:
            entry["is_cdn"] = True
        if cdn_name and not entry["cdn"]:
            entry["cdn"] = cdn_name
        if asn and not entry["asn"]:
            entry["asn"] = asn

    def _add_ip(ips: dict, addr: str, version) -> None:
        bucket = _classify_ip(addr, version)
        if addr not in ips[bucket]:
            ips[bucket].append(addr)

    def _dns_entry(host: str) -> dict:
        return recon_data["dns"]["subdomains"].setdefault(
            host, {"ips": {"ipv4": [], "ipv6": []}, "has_records": True})

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # 1) Apex Domain -> IP, only for the roots whose group includes it.
            if apex_roots:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})-[:RESOLVES_TO]->(i:IP)
                    WHERE d.name IN $apex_roots
                    RETURN d.name AS root, i.address AS address, i.version AS version,
                           i.is_cdn AS is_cdn, i.cdn_name AS cdn_name, i.asn AS asn
                    """,
                    apex_roots=apex_roots, uid=user_id, pid=project_id,
                )
                for record in result:
                    addr = record["address"]
                    if record["root"] == primary:
                        _add_ip(recon_data["dns"]["domain"]["ips"], addr, record["version"])
                        recon_data["dns"]["domain"]["has_records"] = True
                    else:
                        _add_ip(_dns_entry(record["root"])["ips"], addr, record["version"])
                    _hydrate_ip_metadata(addr, record["is_cdn"], record["cdn_name"], record["asn"])

            # 2) Subdomain -> IP relationships
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                      -[:RESOLVES_TO]->(i:IP)
                WHERE d.name IN $domains
                RETURN d.name AS root, s.name AS subdomain, i.address AS address, i.version AS version,
                       i.is_cdn AS is_cdn, i.cdn_name AS cdn_name, i.asn AS asn
                """,
                domains=roots, uid=user_id, pid=project_id,
            )
            for record in result:
                if not _host_allowed(record["root"], record["subdomain"], allowed):
                    continue
                addr = record["address"]
                _add_ip(_dns_entry(record["subdomain"])["ips"], addr, record["version"])
                _hydrate_ip_metadata(addr, record["is_cdn"], record["cdn_name"], record["asn"])

            # Also get subdomains without IPs for the subdomains list
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                WHERE d.name IN $domains
                RETURN collect(DISTINCT s.name) AS subdomains
                """,
                domains=roots, uid=user_id, pid=project_id,
            )
            record = result.single()
            if record:
                recon_data["subdomains"] = [
                    sub for sub in record["subdomains"] or []
                    if _host_allowed(root_for_host(sub, roots), sub, allowed)
                ]

            # 3) BaseURL nodes (for build_target_urls http_probe fallback)
            #    Also fetch is_cdn / cdn / asn so the CDN prefilter in
            #    run_security_checks (collect_cdn_ips, collect_asn_cdn_ips)
            #    can suppress findings on httpx-flagged CDN edges.
            keep = graph_url_scope(session, user_id, project_id, roots, domain_groups,
                                   include_root_domain=include_root_domain)
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                """ + _PROBED_ENDPOINT + """
                RETURN b.url AS url, coalesce(b.status_code, probe.status_code) AS status_code,
                       b.host AS host, coalesce(b.content_type, probe.content_type) AS content_type,
                       coalesce(b.is_cdn, probe.is_cdn) AS is_cdn,
                       coalesce(b.cdn, probe.cdn) AS cdn, coalesce(b.asn, probe.asn) AS asn,
                       coalesce(b.server, probe.server) AS server
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                status_code = record["status_code"]
                if status_code is not None and int(status_code) >= 500:
                    continue
                host = record["host"] or ""
                if not keep(url_host(url, host)):
                    continue
                is_cdn = bool(record["is_cdn"])
                # Resolve host -> first IP so collect_cdn_ips can map URL flag
                # to an IP. dns.subdomains was populated above.
                resolved_ip = None
                sub_entry = recon_data["dns"]["subdomains"].get(host)
                if sub_entry:
                    sub_ips = sub_entry.get("ips", {})
                    resolved_ip = (
                        (sub_ips.get("ipv4") or [None])[0]
                        or (sub_ips.get("ipv6") or [None])[0]
                    )
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": host,
                    "status_code": int(status_code) if status_code is not None else 200,
                    "content_type": record["content_type"] or "",
                    "is_cdn": is_cdn,
                    "cdn": record["cdn"],
                    "asn": record["asn"],
                    "ip": resolved_ip,
                    "server": _field(record, "server"),
                    "technologies": [],
                }
                # If the URL is CDN-flagged AND the cdn name is a reliable
                # edge provider (not generic "aws"/"azure"), also stamp
                # is_cdn on every IP the host resolves to so port_scan.by_ip
                # propagates it. Generic cloud labels are not propagated
                # because the IP often serves the origin app directly.
                if is_cdn and sub_entry:
                    from recon.helpers.cdn_ranges import is_reliable_edge_cdn_name
                    if is_reliable_edge_cdn_name(record["cdn"]):
                        sub_ips = sub_entry.get("ips", {})
                        for ip_addr in (sub_ips.get("ipv4") or []) + (sub_ips.get("ipv6") or []):
                            entry = recon_data["port_scan"]["by_ip"].setdefault(ip_addr, {
                                "ip": ip_addr, "hostnames": [], "ports": [],
                                "is_cdn": False, "cdn": None, "asn": None,
                            })
                            entry["is_cdn"] = True
                            if not entry.get("cdn"):
                                entry["cdn"] = record["cdn"]

            # 3b) The CVE lookup (cve_helpers.run_cve_lookup) reads only by_url
            #     technologies + server and nmap_scan services, and the Nuclei
            #     AI tag selector the first two. Without them a partial run's
            #     "CVE lookup" option looked up nothing.
            by_url = recon_data["http_probe"]["by_url"]
            if by_url:
                for url, techs in _graph_url_technologies(session, user_id, project_id).items():
                    if url in by_url:
                        by_url[url]["technologies"] = techs
            scoped_ips = sorted({
                addr
                for entry in [recon_data["dns"]["domain"], *recon_data["dns"]["subdomains"].values()]
                for addr in (entry["ips"]["ipv4"] + entry["ips"]["ipv6"])
            })
            services = _graph_nmap_services(session, user_id, project_id, scoped_ips)
            if services:
                recon_data["nmap_scan"] = {"services_detected": services}

            # 4) Endpoints with parameters (for DAST mode). run_vuln_scan keeps
            #    only URLs carrying `?` and `=`. The crawlers' raw URLs are not
            #    stored (resource_enum writes no `full_url`), so rebuild each one
            #    from its query Parameters the way build_target_urls_from_resource_enum
            #    does: first sample value, else "1".
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                      -[:HAS_PARAMETER]->(p:Parameter)
                WHERE p.position = 'query' AND p.name IS NOT NULL AND e.path IS NOT NULL
                WITH b, e, p ORDER BY p.name
                RETURN b.url AS baseurl, e.path AS path,
                       collect(DISTINCT [p.name, coalesce(head(p.sample_values), '1')]) AS params
                """,
                uid=user_id, pid=project_id,
            )
            discovered_urls = []
            for record in result:
                base = record["baseurl"]
                params = [(name, str(value)) for name, value in (record["params"] or []) if name]
                if base and params and keep(url_host(base)):
                    discovered_urls.append(f"{base}{record['path']}?{urlencode(params)}")
            # URLs other writers store whole (JS Recon, urlscan) still count.
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.full_url IS NOT NULL
                RETURN e.full_url AS url, e.baseurl AS baseurl
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                if url and keep(url_host(record["baseurl"] or url)):
                    discovered_urls.append(url)
            recon_data["resource_enum"]["discovered_urls"] = list(dict.fromkeys(discovered_urls))

    return recon_data


def _build_graphql_data_from_graph(domains, user_id: str, project_id: str,
                                   settings: dict = None, domain_groups: list = None) -> dict:
    """
    Build recon_data for GraphQL security scanning.

    Populates the three sections discover_graphql_endpoints() reads:
      - http_probe.by_url        (from BaseURL nodes -- headers, status_code)
      - resource_enum.endpoints  ({base_url: [{path, method}]} -- from Endpoint nodes)
      - resource_enum.parameters ({base_url: [{name}]}         -- from Parameter nodes)
      - js_recon.findings        ([{type, path, method}]       -- GraphQL-tagged JsReconFindings)
    Plus metadata.roe so filter_by_roe() still works. `settings` is the run's
    preloaded settings (partial_settings); only a direct caller omits it.

    BaseURLs, Endpoints and Parameters are read project-wide; with
    domain_groups, those on a host under a Domain this run does not cover, or a
    host a literal batch group never listed, are dropped (graph_url_scope). No
    apex rule: these tools never had one.
    """
    from graph_db import Neo4jClient

    if settings is None:
        from recon.project_settings import get_settings
        settings = get_settings()
    roots = _as_roots(domains)
    recon_data = {
        "domain": roots[0] if roots else "",
        "domains": roots,
        "http_probe": {"by_url": {}},
        "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
        "js_recon": {"findings": []},
        "metadata": {
            "roe": {
                "ROE_ENABLED": settings.get("ROE_ENABLED", False),
                "ROE_EXCLUDED_HOSTS": settings.get("ROE_EXCLUDED_HOSTS", []) or [],
            }
        },
    }

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            keep = graph_url_scope(session, user_id, project_id, roots, domain_groups,
                                   apex_filter=False)

            # 1) BaseURLs -> http_probe.by_url
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                """ + _PROBED_ENDPOINT + """
                RETURN b.url AS url,
                       b.host AS host,
                       coalesce(b.status_code, probe.status_code) AS status_code,
                       coalesce(b.content_type, probe.content_type) AS content_type
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                if not url or not keep(url_host(url, record["host"] or "")):
                    continue
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": record["host"] or "",
                    "status_code": int(record["status_code"]) if record["status_code"] is not None else 200,
                    "content_type": record["content_type"] or "",
                    "headers": {},
                }

            # 2) Endpoints grouped by BaseURL -> resource_enum.endpoints
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.path IS NOT NULL
                RETURN b.url AS base_url,
                       collect(DISTINCT {path: e.path, method: coalesce(e.method, 'GET')}) AS endpoints
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                base = record["base_url"]
                if base and keep(url_host(base)):
                    recon_data["resource_enum"]["endpoints"][base] = list(record["endpoints"] or [])

            # 3) Parameters grouped by BaseURL -> resource_enum.parameters
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                      -[:HAS_PARAMETER]->(p:Parameter)
                WHERE p.name IS NOT NULL
                RETURN b.url AS base_url,
                       collect(DISTINCT {name: p.name}) AS parameters
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                base = record["base_url"]
                if base and keep(url_host(base)):
                    recon_data["resource_enum"]["parameters"][base] = list(record["parameters"] or [])

            # 4) GraphQL-tagged JsReconFindings -> js_recon.findings
            result = session.run(
                """
                MATCH (jr:JsReconFinding {user_id: $uid, project_id: $pid})
                WHERE (jr.finding_type IN ['graphql', 'graphql_introspection']
                   OR (jr.finding_type = 'rest' AND toLower(coalesce(jr.path, '')) CONTAINS 'graphql'))
                  // An operator's mute keeps a finding out of the target list. A
                  // node-filter RULE mute does not: it hides noise from display,
                  // and full recon scans its in-memory results either way.
                  AND NOT (jr:Muted AND NOT coalesce(jr.muted_by, '') STARTS WITH 'rule:')
                RETURN jr.finding_type AS type,
                       jr.path AS path,
                       coalesce(jr.method, 'POST') AS method
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                path = record["path"]
                if not path:
                    continue
                recon_data["js_recon"]["findings"].append({
                    "type": record["type"] or "rest",
                    "path": path,
                    "method": record["method"] or "POST",
                })

    return recon_data


def _build_serialized_data_from_graph(domains, user_id: str, project_id: str,
                                      settings: dict = None, domain_groups: list = None) -> dict:
    """Build recon_data for the serialized-object scan from the existing graph.

    The scanner reads three sections (recon/serialized_scan/scanner.py): response
    headers + Set-Cookie (http_probe.by_url), enumerated endpoints/parameters
    (resource_enum.by_base_url) and crawled form fields (resource_enum.forms). A
    partial run has none of these in memory, so this rebuilds them from the nodes
    the full pipeline persisted:
      - Header nodes (Endpoint-[:HAS_HEADER]->Header) carry EVERY response header,
        Set-Cookie included, keyed by the response URL - the main detection path.
      - Parameter.sample_values (<=5, resource_mixin) carry example values.
      - Endpoint.form_input_names carry form field NAMES (values are not persisted,
        so a serialized blob baked into a hidden field's value cannot be recovered
        from the graph - only its name, which still flags a sink-named field).
    Scope is the same graph_url_scope the other builders use. `settings` is the
    run's preloaded settings; only a direct caller omits it.
    """
    from graph_db import Neo4jClient

    from recon.partial_recon_modules.helpers import _should_include_root_domain

    if settings is None:
        from recon.project_settings import get_settings
        settings = get_settings()
    roots = _as_roots(domains)
    include_root_domain = _should_include_root_domain(settings)
    recon_data = {
        "domain": roots[0] if roots else "",
        "domains": roots,
        "http_probe": {"by_url": {}},
        "resource_enum": {"endpoints": {}, "parameters": {}, "by_base_url": {},
                          "forms": [], "discovered_urls": []},
        "metadata": {
            "roe": {
                "ROE_ENABLED": settings.get("ROE_ENABLED", False),
                "ROE_EXCLUDED_HOSTS": settings.get("ROE_EXCLUDED_HOSTS", []) or [],
            }
        },
    }
    if not roots:
        return recon_data

    by_url = recon_data["http_probe"]["by_url"]
    by_base = recon_data["resource_enum"]["by_base_url"]

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # apex_filter default (True): the serialized partial honours Include
            # Root Domain, unlike the GraphQL builder which never had an apex rule.
            keep = graph_url_scope(session, user_id, project_id, roots, domain_groups,
                                   include_root_domain=include_root_domain)

            # 1) BaseURL nodes seed by_url (so a root with headers only on "/" is covered).
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                """ + _PROBED_ENDPOINT + """
                RETURN b.url AS url, b.host AS host,
                       coalesce(b.status_code, probe.status_code) AS status_code,
                       coalesce(b.content_type, probe.content_type) AS content_type
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                if not url or not keep(url_host(url, record["host"] or "")):
                    continue
                by_url[url] = {
                    "url": url,
                    "host": record["host"] or "",
                    "status_code": int(record["status_code"]) if record["status_code"] is not None else 200,
                    "content_type": record["content_type"] or "",
                    "headers": {},
                }

            # 2) Response headers (Set-Cookie included) keyed by the response URL the
            # header came from; this is where the serialized blobs ride. A header on
            # an endpoint URL not seen as a BaseURL still gets its own by_url entry.
            result = session.run(
                """
                MATCH (e:Endpoint {user_id: $uid, project_id: $pid})-[:HAS_HEADER]->(h:Header)
                WHERE h.name IS NOT NULL
                RETURN coalesce(h.baseurl, e.baseurl) AS url, e.host AS host,
                       h.name AS name, h.value AS value
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                if not url or not keep(url_host(url, record["host"] or "")):
                    continue
                entry = by_url.setdefault(url, {
                    "url": url, "host": record["host"] or url_host(url),
                    "status_code": 200, "content_type": "", "headers": {},
                })
                # One header name can repeat (several Set-Cookie); keep every value.
                entry.setdefault("headers", {}).setdefault(record["name"], []).append(
                    str(record["value"]) if record["value"] is not None else "")

            # 3) Endpoints + their parameters (names AND sample_values) -> by_base_url,
            # the exact shape _scan_resource_enum / _iter_params read.
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.path IS NOT NULL
                OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(p:Parameter)
                WHERE p.name IS NOT NULL
                RETURN b.url AS base, b.host AS host, e.path AS path,
                       coalesce(e.method, 'GET') AS method,
                       collect(DISTINCT {name: p.name, sample_values: coalesce(p.sample_values, [])}) AS params
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                base = record["base"]
                if not base or not keep(url_host(base, record["host"] or "")):
                    continue
                params = {}
                for p in record["params"] or []:
                    name = p.get("name")
                    if not name:
                        continue
                    samples = [s for s in (p.get("sample_values") or []) if isinstance(s, str)]
                    params[str(name)] = {"sample_values": samples}
                endpoints = by_base.setdefault(base, {"endpoints": {}})["endpoints"]
                endpoints[record["path"]] = {"method": record["method"], "parameters": params}

            # 4) Form field names (values are not persisted in the graph) -> forms.
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.form_input_names IS NOT NULL AND size(e.form_input_names) > 0
                RETURN b.url AS base, b.host AS host, e.path AS path,
                       coalesce(e.method, 'GET') AS method, e.form_input_names AS names
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                base = record["base"]
                if not base or not keep(url_host(base, record["host"] or "")):
                    continue
                endpoint_url = base.rstrip("/") + "/" + str(record["path"] or "").lstrip("/")
                recon_data["resource_enum"]["forms"].append({
                    "found_at": endpoint_url,
                    "action": endpoint_url,
                    "method": record["method"],
                    "inputs": [{"name": n, "value": ""} for n in (record["names"] or []) if n],
                })

    return recon_data

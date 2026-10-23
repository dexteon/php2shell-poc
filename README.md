# php2shell: research and detection tooling for CVE-2026-109618 / CVE-2026-109619

Security research code for the two critical PHP core vulnerabilities disclosed on 21 October 2026. Written for vulnerability research and defensive triage: identify affected systems, understand the exploit chain, and verify patches. For authorized testing and educational use only. See the [disclaimer](#disclaimer) before running anything.

- CVE-2026-109618 ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)): heap use-after-free in the `session.upload_progress` cleanup path
- CVE-2026-109619 ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)): corrupted session hash-table destructor leading to arbitrary function call

Vendor advisories and patches: [php.net security archive](https://www.php.net/archive/2026.php), patch commit [3584a98](https://github.com/php/php-src/commit/3584a98bda).

## What this repo contains

`php2shell.py` implements two independent chains that reach the same bugs, plus a read-only fingerprint mode that sends no exploit traffic at all:

| Mode | What it does | Traffic |
|------|--------------|---------|
| `check` | Fingerprints PHP version, SAPI type, and `upload_progress` state from response headers | Plain GET requests |
| `exploit --vector uaf` | CVE-2026-109618 chain: session bucket UAF into a forged `zend_fcall_info` | Crafted multipart POSTs |
| `exploit --vector pdetector` | CVE-2026-109619 chain: forged `pDestructor` into `zif_system` (stub; needs calibration data) | Crafted multipart POSTs |
| `syms` | Extracts `zval_ptr_dtor` / `zend_call_function` offsets and their delta from a `libphp.so` ELF | Local binary analysis only |

The default demo command is `id` (prints `uid=...` and exits). Nothing in this repo drops a shell, writes files to the target, or persists anything.

## Quick start

### Check mode (read-only fingerprint)

Determine whether a target runs an affected PHP version without sending exploit traffic:

```bash
python3 php2shell.py check -u http://target.example.com/
python3 php2shell.py check -f targets.txt -o results.jsonl
```

Output:
```
[VULNERABLE] http://target.example.com/  PHP 8.4.26  SAPI mod_php
[PATCHED]   http://fixed.example.com/     PHP 8.4.27  SAPI mod_php
```

### UAF exploit against the Docker lab

The `uaf` vector exercises CVE-2026-109618 against a local lab container:

```bash
docker compose -f docker/docker-compose.yml up -d
python3 php2shell.py exploit -u http://127.0.0.1:8088/index.php --vector uaf --command id
```

The command must fit in 8 bytes (the forged record is 16 bytes total; 8 go to the leaked pointer). `id` is the default.

### Symbol extraction

```bash
python3 php2shell.py syms /path/to/libphp.so
```

Prints `dtor_offset`, `call_offset`, and `delta` using readelf, objdump, or a byte-scan fallback. Useful for building the per-build calibration tables that real targets need.

### Command line options

```
python3 php2shell.py --help
```

Check mode:
- `-u URL` single target URL
- `-f FILE` target list file (one URL per line, `#` comments allowed)
- `-o FILE` JSONL output file
- `-w N` parallel workers (default 5)
- `-t SECS` HTTP timeout (default 10)
- `--proxy HOST:PORT` SOCKS5 proxy
- `--json` machine-readable JSON output
- `-q` quiet mode

Exploit mode:
- `-u URL` target URL (required)
- `-c CMD` command to execute (default `id`, max 8 bytes for UAF)
- `--vector uaf|pdetector` attack vector (default `uaf`)
- `--dtor 0x...` DTOR leak address for UAF mode
- `--delta 0x...` DTOR-to-call delta for UAF mode
- `--syms PATH` extract offsets from a `libphp.so` before running
- `--calib FILE` calibration file (pDetector)
- `-q` quiet mode

## The two chains, briefly

The original php2shell chain (CVE-2026-109619, the `pdetector` vector) works in four stages over plain HTTP, all through `session.upload_progress`:

1. Worker rotation. Force an OOM crash in an Apache prefork worker. The replacement process inherits the same address space layout.
2. Heap leak. A crafted multipart POST triggers an out-of-bounds read in session cookie handling, leaking heap chunk addresses through `Set-Cookie`.
3. libphp leak. A corrupted pointer in session state leaks the `pDestructor` address. Since `pDestructor = libphp_base + dtor_offset`, this reveals the libphp base and therefore `zif_system`.
4. Call. Forge a hash table whose destructor points at `system()` with the embedded command.

The PHP-UP-2026 chain (CVE-2026-109618, the `uaf` vector) takes a different route into the same session machinery. Two bucket pointers cached during upload-progress tracking survive into a freed array. A second `update()` call destroys the previous session tree through `zval_ptr_dtor`, the freed bucket is reclaimed with attacker-shaped data, and the stale pointer lands a forged `zend_fcall_info` / `zend_internal_function` that ends up calling `system()`. It needs `session.upload_progress.enabled = 1` (the PHP default) and works on both mod_php and php-fpm.

Full plain-English writeup of the original chain: see the [References](#references) section.

## Platform scope

The exploit stages are Linux-only:

- Stage 0 of the pdetector chain requires `fork()` copy-on-write (Apache mod_php prefork)
- Offsets index `libphp.so`, an ELF shared object
- The `id` payload is POSIX

The UAF vector avoids the fork requirement and can work over php-fpm. The underlying bugs exist in PHP on every platform; only the delivery mechanics are Linux-specific.

ASLR is not a barrier for either chain: the leaks in stage 2 read the heap and libphp base addresses off the wire.

## Affected versions

All PHP branches with `session.upload_progress` compiled in (introduced in 5.4.0):

| Branch | Vulnerable | Fixed |
|--------|------------|-------|
| 8.5 | <= 8.5.11 | 8.5.12 |
| 8.4 | <= 8.4.26 | 8.4.27 |
| 8.3 | <= 8.3.35 | 8.3.36 |
| 8.2 | <= 8.2.34 | 8.2.35 |
| 8.1 and older | All | EOL, no patch |

## Detection and mitigation

### Check a host

```bash
php -v
# or remotely:
curl -sI https://example.com/ | grep X-Powered-By
```

### Patch

```bash
apt update && apt upgrade php*
systemctl restart apache2  # or php-fpm
```

### Mitigate without patching

```ini
; php.ini or FPM pool config
session.upload_progress.enabled = Off
session.use_only_cookies = On
```

For CVE-2026-109618, lowering `post_max_size` and raising `memory_limit` also shrinks the OOM surface:

```ini
post_max_size = 8M
memory_limit = 256M
```

### Monitor

Watch Apache and FPM error logs for unexpected child crashes (SIGABRT, SIGSEGV) during normal traffic. Multipart POST requests carrying `PHP_SESSION_UPLOAD_PROGRESS` fields to endpoints that never expected file uploads are the signature to alert on.

## Files

| Path | Purpose |
|------|---------|
| `php2shell.py` | Fingerprint, exploit, and symbol-extraction tooling |
| `docker/docker-compose.yml` | Vulnerable lab container (Apache prefork, PHP 8.x) |
| `docker/php.ini` | Lab PHP configuration |
| `docker/apache.conf` | Single-worker prefork config |
| `docker/offsets.py` | Reads libphp offsets from the container ELF |
| `docker/www/index.php` | Minimal target page (`<?php echo "OK"; ?>`) |

## References

- [PHP security announcement, 21 October 2026](https://www.php.net/archive/2026.php)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w): CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp): CVE-2026-109619
- [Patch commit 3584a98](https://github.com/php/php-src/commit/3584a98bda)
- [PHP-UP-2026 analysis, J4ck3LSyN](https://jackalsyn.com/posts/php-up-2026.html) (research: Andrew Dorman, Arch and Yuki)
- [Sansec analysis](https://sansec.io/research/php2shell)

## Contact

Questions or concerns about this research: open a GitHub issue on this repo, or reach the maintainer profile at [github.com/dexteon](https://github.com/dexteon).

## License

MIT

## Disclaimer

This code is for authorized security testing, research, and education only. Do not run it against systems you do not own or lack written permission to test. The maintainers provide it to help defenders identify exposed systems and verify patches. Tested against the local Docker lab (Apache 2.4.x, Debian 12, PHP 8.x); real-world targets with different compile-time options, ASLR configurations, or kernel parameters need their own calibration and may not work unmodified.


<!-- ca-tracked-link -->
[cyberautomations.com](https://cyberautomations.com/?utm_source=github&utm_medium=readme&utm_campaign=php2shell-poc)

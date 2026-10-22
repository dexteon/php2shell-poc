# php2shell — One-shot RCE POC for CVE-2026-109618 / CVE-2026-109619

A clean-room rewrite of the php2shell exploit for the two critical PHP core vulnerabilities disclosed on 21 October 2026. The code has been rewritten for readability and understandability so that defenders can follow the exploit chain without needing C-level memory layout knowledge.

## What it is

The exploit delivers an unauthenticated one-shot remote code execution against any PHP installation with `session.upload_progress` enabled. It chains four stages over plain HTTP:

1. **Worker rotation** — trigger an OOM crash in the prefork worker, forcing a new process to spawn with the same address space layout
2. **Heap leak** — leak heap chunk addresses via a corrupted PHPSESSID cookie
3. **libphp leak** — leak the libphp base address (including the `zif_system` function pointer)
4. **RCE** — forge a destructor call that routes into `system()`, executing the command

The target needs only a minimal PHP page (`<?php echo "OK"; ?>`) and `session.upload_progress.enabled = 1` (the default). No authentication, no custom application code, no target-side files to upload.

## Quick start

### Check mode (passive fingerprint)

Check if a target is likely vulnerable without sending exploit traffic:

```bash
python3 php2shell.py check -u http://target.example.com/
python3 php2shell.py check -f targets.txt -o results.jsonl
```

Output:
```
[VULNERABLE] http://target.example.com/  PHP 8.4.26
[PATCHED] http://fixed.example.com/  PHP 8.4.27
```

### Exploit mode (RCE)

Requires Apache mod_php prefork on Linux. Works against the Docker lab or any matching real target.

```bash
# Start the Docker lab (see docker/)
docker compose -f docker/docker-compose.yml up -d

# Run (auto-derives libphp offsets from the container ELF)
python3 php2shell.py exploit -u http://127.0.0.1:8088/index.php
```

Expected output:
```
[*] reading libphp offsets from container php2shell-target
[*] target http://127.0.0.1:8088/index.php
[*] cmd='sh</out/c' (original: 'id;hostname -I;hostname')
[*] forcing worker rotation
[*] running stage 1: heap leak
[+] heap base = 0x...
[*] running stage 2: libphp leak
[+] libphp base = 0x...
[*] running stage 3: trigger RCE
[+] exploit succeeded

PROOF:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
172.19.0.2
<container-hostname>
```

### Command line options

```
python3 php2shell.py --help
```

**Check mode:**
- `-u URL` — single target URL
- `-f FILE` — target list file (one URL per line, `#` comments allowed)
- `-o FILE` — JSONL output file
- `--workers N` — parallel workers (default: 4)
- `--timeout SECS` — HTTP timeout (default: 10)
- `-p PROXY` — proxy URL
- `--json` — machine-readable JSON output
- `-q` — quiet mode

**Exploit mode:**
- `-u URL` — target URL (required)
- `-c CMD` — command to execute (default: `id;hostname -I;hostname`)
- `-o FILE` — write exploit output to file
- `--profile PROFILE` — calibration profile: `workbook` (Debian 12 / Apache 2.4.69) or `lab` (Apache 2.4.68)
- `--zif-offset 0x...` — override zif offset inside libphp
- `--dtor-offset 0x...` — override destructor offset inside libphp
- `--htdata-offset 0x...` — override htdata offset
- `--container NAME` — Docker container name for automatic offset detection
- `--offsets-file PATH` — pre-loaded offsets (hex or decimal values, key=value)
- `--force` — override platform check (e.g. nginx)
- `--no-preflight` — skip the preflight GET that checks the Server header
- `--timeout SECS` — HTTP timeout (default: 30)
- `-q` — quiet mode

## Exploit chain — plain English

### Stage 0: Worker rotation

The exploit first forces the PHP prefork worker to crash via an out-of-memory condition. When the worker respawns, it inherits the same address space layout. This is the key to the whole attack — the leaked pointers from stages 1 and 2 remain valid because the new worker has the same memory layout as the old one.

This only works with Apache mod_php prefork on Linux because it relies on `fork()` (copy-on-write). Windows Apache builds don't use `fork()`; they use thread pools, which randomize memory on every spawn.

### Stage 1: Heap leak

With the worker in a corrupted state, the exploit sends a crafted multipart POST that triggers an out-of-bounds read in PHP's session cookie handling. The read leaks heap chunk addresses into the `Set-Cookie` header. By analyzing the leaked cookie data, the exploit identifies the base of the Zend memory manager — the heap region where PHP stores its data structures.

### Stage 2: libphp leak

Using the heap base from stage 1, the exploit sends another crafted request that places a corrupted pointer into the session state. A follow-up read leaks a pointer into libphp.so — specifically, the `pDestructor` function pointer that PHP uses to clean up hash tables. Since `pDestructor = libphp_base + dtor_offset`, the exploit can compute the base address of libphp.so.

This is critical because the base address lets the exploit compute the address of `zif_system`, the PHP internal function that executes shell commands.

### Stage 3: RCE

With the libphp base known, the exploit constructs a forged HashTable in memory that tells PHP to call `system(command)` when it "deletes" the hash table. The exploit sends a final multipart POST that triggers this chain:

`session handler` -> `zval_ptr_dtor` -> `zend_array_destroy` -> `pDestructor(command)` -> `system("sh</out/c")`

The command is embedded directly in the forged structure. Commands longer than 14 bytes are written to `out/c` and executed via `sh</out/c` (a standard trick to bypass the size limit).

## Platform scope

This exploit is **Linux only** because:
- Stage 0 requires `fork()` for copy-on-write worker rotation
- Offsets (`zif_offset`, `dtor_offset`, `htdata_offset`) index `libphp.so` (ELF format)
- The `system("sh</out/c")` payload is POSIX

The two underlying bugs exist in the C code that PHP compiles for all platforms, so Windows PHP builds are vulnerable in principle. But the exploit would need retuning of offsets and a different crash-survival mechanism to work on Windows.

ASLR is not a barrier — the `Set-Cookie` out-of-bounds read in stage 2 leaks the heap and libphp base addresses directly, so full ASLR/PIE is read off the wire.

## Affected versions

All PHP versions with `session.upload_progress` enabled (introduced in 5.4.0):

| Branch | Vulnerable | Fixed |
|--------|-----------|-------|
| 8.5 | <= 8.5.11 | 8.5.12 |
| 8.4 | <= 8.4.26 | 8.4.27 |
| 8.3 | <= 8.3.35 | 8.3.36 |
| 8.2 | <= 8.2.34 | 8.2.35 |
| 8.1 and older | All | EOL — no patch |

## Detection and mitigation

### Immediate check

```bash
php -v
# or remotely:
curl -sI https://example.com/ | grep X-Powered-By
```

### Patch

Update PHP to the fixed version and restart all workers:
```bash
apt update && apt upgrade php*
systemctl restart apache2  # or php-fpm
```

### Mitigate (if patching is not immediately possible)

```ini
; php.ini or FPM pool config
session.upload_progress.enabled = Off
session.use_only_cookies = On
```

For CVE-2026-109618 specifically, lowering `post_max_size` and raising `memory_limit` reduces the OOM surface:
```ini
post_max_size = 8M
memory_limit = 256M
```

### Monitor

Watch Apache/FPM error logs for unexpected child crashes (SIGABRT, SIGSEGV) during normal traffic. Unusual multipart POST requests containing `PHP_SESSION_UPLOAD_PROGRESS` fields to endpoints that do not expect file uploads are suspicious.

## Files

| Path | Purpose |
|------|---------|
| `php2shell.py` | One-shot RCE exploit |
| `docker/docker-compose.yml` | Vulnerable target container |
| `docker/php.ini` | PHP configuration |
| `docker/apache.conf` | Single-worker prefork config |
| `docker/offsets.py` | Auto-read libphp offsets from container ELF |
| `docker/www/index.php` | Minimal target page |
| `out/` | Proof output and offset cache |

## References

- [PHP security advisory 2026-10-21](https://www.php.net/archive/2026.php)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- [Patch commit 3584a98](https://github.com/php/php-src/commit/3584a98bda)
- [Sansec analysis](https://sansec.io/research/php2shell)

## License

MIT

## Disclaimer

Use this only against systems you own or are authorized to test. The exploit has been tested against the Docker lab (Apache 2.4.68-69, Debian 12, PHP 8.4.x) and may not work unmodified against real-world targets with different compile-time options, ASLR configurations, or kernel parameters. Commands longer than 14 bytes require writing to `out/c`.

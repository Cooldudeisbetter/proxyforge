# proxyforge

**Parse, validate, classify, rotate and use proxies from Python or the command line.**

`proxyforge` takes the messy proxy lists you actually have (five different formats mixed in one
file, scraped HTML, a URL) and turns them into a clean, checked, rotating pool, and can tell you
whether each exit IP looks **residential**, **datacenter** or **mobile**.

- **Parses everything**: `host:port`, `user:pass@host:port`, `host:port:user:pass`,
  `user:pass:host:port`, `scheme://...`, IPv6, percent-encoded passwords, even passwords containing `@`
- **Checks fast**: threaded or asyncio, records latency and exit IP, auto-detects http / socks5 / socks4
- **Classifies exit IPs**: residential / datacenter / mobile with a confidence score and reasons
- **Rotates properly**: round-robin, random, least-used, latency-weighted, or sticky per account;
  failing proxies are banned with exponential backoff and requests fail over automatically
- **Plugs into your stack**: requests, httpx, aiohttp, Playwright, curl, Chrome
- **Small and typed**: one module, one required dependency (`requests`), fully type-annotated,
  Python 3.9+

> **Status: beta (0.x).** The parser, pool and CLI are covered by an offline test suite (about 90%
> coverage; the CI matrix runs it on Linux, macOS and Windows across Python 3.9 to 3.13). SOCKS
> support and the classification heuristics have not been validated against a wide range of
> real-world providers yet, so treat classification as a strong hint, not proof (see
> [How classification works](#how-classification-works)).

## Contents

[Install](#install) ·
[Quick start](#quick-start) ·
[Command line](#command-line) ·
[Input formats](#input-formats) ·
[Checking proxies](#checking-proxies) ·
[Rotating pool](#rotating-pool) ·
[Residential vs datacenter](#how-classification-works) ·
[Using proxies with other clients](#using-proxies-with-other-clients) ·
[API reference](#api-reference) ·
[Security and privacy](#security-and-privacy) ·
[Development](#development)

## Install

```bash
pip install proxyforge                 # core (requests)
pip install "proxyforge[socks]"        # + socks4/socks5 via requests
pip install "proxyforge[async]"        # + httpx[socks]: acheck_many() and pool.arequest()
pip install "proxyforge[all]"          # everything
```

From a clone: `pip install -e ".[dev]"`. Before the first PyPI release you can install straight
from GitHub: `pip install "git+https://github.com/OWNER/proxyforge"`.

## Quick start

```python
import proxyforge as pk

# 1. Parse. Mixed formats are fine; duplicates and bad lines are reported, not fatal.
found = pk.load_file("proxies.txt")  # or pk.load_url(...), pk.parse_many(text), pk.extract(html)
print(f"{len(found)} proxies, {found.duplicates} duplicates, {len(found.errors)} bad lines")

# 2. Check which ones work (threaded; use `await pk.acheck_many(...)` for asyncio).
results = pk.check_many(found.proxies, workers=100, timeout=8)
alive = [r.proxy for r in results if r.ok]

# 3. Rotate through them. Dead proxies are banned automatically; requests retry elsewhere.
pool = pk.ProxyPool(alive, strategy="fastest")
resp = pool.request("GET", "https://example.com", retries=3)
print(resp.status_code)

# 4. Keep only residential ones (free ip-api.com lookups, ~40/min).
pool.classify(rotation_samples=3)
residential = pool.only("residential")
```

One account, one IP (sticky sessions):

```python
pool = pk.ProxyPool(alive, strategy="sticky")
resp = pool.request("GET", url, key="account_42")  # same key -> same proxy; fails over if it dies
```

## Command line

```bash
proxyforge parse    list.txt                                     # report bad lines and duplicates
proxyforge convert  list.txt --to user:pass@host:port -o out.txt # reformat (also json, csv)
proxyforge check    list.txt --workers 200 -o alive.txt          # keep working proxies, fastest first
proxyforge check    list.txt --detect                            # try http, then socks5, then socks4
proxyforge check    list.txt --classify --kind residential -o resi.txt
proxyforge check    https://example.com/list.txt --max-latency 1500 --to json -o report.json
cat list.txt | proxyforge check - --scheme socks5
python -m proxyforge --version
```

| Option (`check`) | Meaning |
| --- | --- |
| `--url URL` | Endpoint used to test proxies (default `https://api.ipify.org?format=json`) |
| `--timeout S` / `--workers N` | Per-proxy timeout (8s) and thread count (100) |
| `--detect` | Try http, socks5, socks4 for each proxy and keep the working scheme |
| `--max-latency MS` | Drop proxies slower than this |
| `--classify` | Tag survivors as residential / datacenter / mobile |
| `--kind KIND...` | Keep only these kinds (implies `--classify`) |
| `--rotation-samples N` | Extra requests per proxy to see whether its exit IP rotates |
| `--api-key KEY` | ip-api.com pro key (HTTPS, higher limits) |
| `--to FORMAT` / `-o FILE` | Output format (`url`, `host:port`, `host:port:user:pass`, `user:pass@host:port`, `user:pass:host:port`, `json`, `csv`) and destination |
| `-v` / `-vv` | Log to stderr (info / debug) |

Progress and summaries go to **stderr**, results to **stdout** (or `-o`), so it pipes cleanly.
Exit codes: `0` success, `1` `check` found no working proxy, `2` the input could not be loaded.

## Input formats

| Example | Notes |
| --- | --- |
| `1.2.3.4:8080` | Scheme defaults to `http` (`--scheme` / `default_scheme=` to change) |
| `http://user:pass@1.2.3.4:8080` | Any of `http https socks4 socks4a socks5 socks5h` |
| `user:pass@1.2.3.4:8080` | |
| `1.2.3.4:8080@user:pass` | |
| `1.2.3.4:8080:user:pass` | Hostname or IP first |
| `user:pass:1.2.3.4:8080` | Detected by where the port is |
| `[2001:db8::1]:8080` | IPv6 |
| `us%40er:p%3Aw@host.io:80` | Percent-encoding is decoded |
| `user:pa@ss@host.io:3128` | Password containing `@` |

Lists may contain several entries per line (whitespace separated) and `#`, `//` or `;` comments.
Truly ambiguous entries (for example `1.2.3.4:80@bob:1234`) are resolved by preferring the side
that is an IP address.

## Checking proxies

```python
res = pk.check_proxy(proxy, url="https://api.ipify.org?format=json", timeout=8)
res.ok, res.latency_ms, res.ip, res.error  # a CheckResult
proxy.latency_ms, proxy.exit_ip  # also recorded on the Proxy (smoothed latency)

pk.check_many(proxies, workers=100, progress=lambda done, total, r: ...)
await pk.acheck_many(proxies, concurrency=200)  # needs the [async] extra
pk.detect_scheme(proxy)  # -> working copy with the right scheme, or None
```

A proxy counts as working when the check URL answers `200`. Error text never contains the proxy
username or password.

## Rotating pool

```python
pool = pk.ProxyPool(proxies, strategy="round_robin", cooldown=60, max_failures=3)
```

| Strategy | Behaviour |
| --- | --- |
| `round_robin` | Cycle through available proxies |
| `random` | Uniform random (`seed=` for reproducibility) |
| `least_used` | Always the least-used proxy |
| `fastest` | Random, weighted by `1 / latency`; untested proxies get an average weight |
| `sticky` | `pool.get(key)` always maps the same key to the same proxy (rendezvous hashing), with failover |

After `max_failures` consecutive failures a proxy is banned for `cooldown * 2**n` seconds (capped
by `max_cooldown`). `get()` raises `NoProxyAvailable` when everything is banned.

```python
proxy = pool.get()  # pick one yourself...
pool.report_success(proxy, latency_ms=120)  # ...and feed results back
pool.report_failure(proxy)

with pool.lease() as proxy:  # exception -> failure, clean exit -> success
    ...

r = pool.request(
    "GET", url, retries=3
)  # requests; rotates on network errors and 407/429/502/503/504
r = await pool.arequest("GET", url)  # httpx
s = pool.session(key="acct")  # requests.Session pinned to one proxy
```

`request()` raises `PoolExhausted` after the last attempt fails. Malformed URLs raise immediately
instead of being blamed on the proxy. `pool.stats()` returns masked per-proxy statistics.

## How classification works

```python
c = pk.classify(proxy, rotation_samples=5)
c.kind  # "residential" | "datacenter" | "mobile" | "unknown"
c.confidence  # 0.0 - 1.0
c.rotates  # did the exit IP change between connections? (None if not sampled)
c.reasons  # human-readable evidence
pk.classify_many(proxies)  # threaded, globally rate-limited
pool.classify()
pool.only("residential", "mobile")
```

Signals combined:

1. **ip-api.com flags**: `hosting` -> datacenter, `mobile` -> mobile carrier.
2. **ISP / ASN name** matched against well-known hosting providers (AWS, OVH, Hetzner, ...).
3. **Reverse DNS**: `dyn-`, `cpe-`, `pool-`, `dhcp-` style names support residential; `vps`,
   `compute`, `server` style names indicate a datacenter.
4. **Rotation sampling** (optional): residential pools usually hand out a different IP, often on a
   different ISP, per connection.

Limits to keep in mind:

- It is a **heuristic**. Static "ISP proxies" that live in a datacenter but are announced under a
  consumer ISP's ASN look residential.
- `known_proxy` reports that the IP appears in ip-api's proxy database. Commercial residential
  pools are often listed there, so this is informational and does not lower the score.
- The free ip-api tier is HTTP-only, non-commercial, and capped at about 45 requests per minute.
  `proxyforge` rate-limits itself to 40/min and caches results, so large lists take time. Pass
  `api_key=` for the paid HTTPS endpoint. Each lookup sends the exit IP to ip-api.com.

## Using proxies with other clients

```python
requests.get(url, proxies=proxy.requests_dict())
httpx.AsyncClient(proxy=proxy.httpx_url())
aiohttp_session.get(url, **proxy.aiohttp_kwargs())  # http proxies; use aiohttp-socks for socks
playwright.chromium.launch(proxy=proxy.playwright())
subprocess.run(["curl", *proxy.curl_args(), url])
proxy.chrome_arg()  # --proxy-server=...  (Chrome ignores credentials here)
proxy.format("host:port:user:pass")  # any list format
```

Export with `pk.export_txt(proxies, fmt)`, `pk.export_json(...)`, `pk.export_csv(...)`.

## API reference

| Name | Purpose |
| --- | --- |
| `Proxy` | Host, port, scheme, credentials, plus stats (`latency_ms`, `exit_ip`, `kind`, `isp`, `asn`, `country`, ...). `url()`, `masked()`, `format()`, client adapters |
| `parse(line)` / `parse_many(text)` | One proxy / many (returns `ParseResult` with `.proxies`, `.errors`, `.duplicates`) |
| `extract(text)` | Find proxies in free text or HTML tables |
| `load_file(path)` / `load_url(url)` | Read a list; `load_url` is http(s) only and size-capped |
| `check_proxy` / `check_many` / `acheck_many` / `detect_scheme` | Validate proxies |
| `ProxyPool` | Rotation, bans, retries, `request`, `arequest`, `session`, `lease`, `classify`, `only`, `stats` |
| `classify` / `classify_ip` / `classify_many` / `lookup_ip` / `reverse_dns` | Exit-IP classification |
| `export_txt` / `export_json` / `export_csv` | Serialize |
| `ProxyParseError`, `NoProxyAvailable`, `PoolExhausted` | Exceptions |

Everything is type-annotated and documented with docstrings (`help(proxyforge.ProxyPool)`).
Enable logs with `logging.getLogger("proxyforge").setLevel(logging.DEBUG)`; the library is silent
by default.

## Security and privacy

- `repr(proxy)` and `proxy.masked()` hide credentials; `str(proxy)` and `proxy.url()` include them
  because HTTP clients need them. Error messages and `stats()` output are scrubbed.
- The CLI creates output files with mode `0600` (owner only) on POSIX. Keep proxy lists out of git;
  the bundled `.gitignore` covers common names.
- `proxy.curl_args()` exposes the password in the process list while curl runs.
- Classification sends exit IPs to ip-api.com (plain HTTP on the free tier).
- `load_url()` refuses non-http(s) URLs and downloads larger than 20 MB (configurable).

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

**Responsible use.** Only use proxies you are authorized to use, and respect the terms of the
services you reach through them. This library does not bypass authentication, rate limits or
access controls.

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest --cov
```

Tests are fully offline (local fake proxy and ip-api servers). See [CONTRIBUTING.md](CONTRIBUTING.md)
and [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)

"""
proxyforge - parse, validate, classify, rotate and use proxies.

Features
  * Parse almost every common proxy format (host:port, user:pass@host:port,
    host:port:user:pass, user:pass:host:port, scheme://..., [ipv6]:port, ...)
  * Extract proxies out of arbitrary text / scraped HTML
  * Convert to requests / httpx / aiohttp / Playwright / curl formats
  * Check proxies concurrently (threads or asyncio) with latency + exit IP
  * Auto-detect scheme (http / socks5 / socks4)
  * Classify exit IPs as residential / datacenter / mobile (free ip-api.com lookups,
    reverse DNS, ISP heuristics, optional rotation sampling) with a confidence score
  * Rotating pool: round_robin, random, least_used, fastest, sticky (per key)
    with failure tracking, exponential cool-down bans and automatic retries
  * Export to txt (any format) / json / csv
  * Export a proxy as a Chrome extension (MV3, with proxy auth)
  * CLI:  proxyforge parse|check|convert|extension ... (or: python -m proxyforge)

Dependencies: ``requests`` (core); ``requests[socks]`` for socks4/socks5;
``httpx[socks]`` for async checking and ``pool.arequest()``.
Parsing and pooling logic itself is pure standard library.
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import logging
import os
import random
import re
import socket
import struct
import sys
import threading
import time
import zipfile
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from hashlib import blake2b
from typing import Any, Callable, Optional, Union
from urllib.parse import quote, unquote

__version__ = "0.3.0"
_UA = f"proxyforge/{__version__}"
log = logging.getLogger("proxyforge")
log.addHandler(logging.NullHandler())
__all__ = [
    "CheckResult",
    "Classification",
    "Geo",
    "NoProxyAvailable",
    "ParseResult",
    "PoolExhausted",
    "Proxy",
    "ProxyParseError",
    "ProxyPool",
    "__version__",
    "acheck_many",
    "build_chrome_extension",
    "check_many",
    "check_proxy",
    "classify",
    "classify_ip",
    "classify_many",
    "crx_extension_id",
    "detect_scheme",
    "export_csv",
    "export_json",
    "export_txt",
    "extract",
    "geolocate",
    "geolocate_ip",
    "geolocate_many",
    "load_file",
    "load_url",
    "locale_for_country",
    "lookup_ip",
    "main",
    "parse",
    "parse_many",
    "reverse_dns",
]

SCHEMES = {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}
DEFAULT_CHECK_URL = "https://api.ipify.org?format=json"
FORMATS = ("url", "host:port", "host:port:user:pass", "user:pass@host:port", "user:pass:host:port")


class ProxyParseError(ValueError):
    pass


class NoProxyAvailable(RuntimeError):
    """Every proxy in the pool is currently banned (or the pool is empty)."""


class PoolExhausted(RuntimeError):
    """All retry attempts failed."""


# --------------------------------------------------------------------------
# Proxy object
# --------------------------------------------------------------------------
@dataclass(eq=False)
class Proxy:
    host: str
    port: int
    scheme: str = "http"
    username: Optional[str] = None
    password: Optional[str] = None
    # runtime stats (not part of identity)
    latency_ms: Optional[float] = None
    successes: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    bans: int = 0
    banned_until: float = 0.0
    uses: int = 0
    last_checked: float = 0.0
    exit_ip: Optional[str] = None
    kind: Optional[str] = None  # residential | datacenter | mobile | unknown (see classify)
    isp: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    geo: Optional[Geo] = None  # filled by geolocate()
    meta: dict[str, Any] = field(default_factory=dict)

    # identity -------------------------------------------------------------
    @property
    def key(self) -> tuple[Any, ...]:
        return (self.scheme, self.host, self.port, self.username, self.password)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Proxy) and self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)

    # formatting -----------------------------------------------------------
    @property
    def _host_part(self) -> str:
        return f"[{self.host}]" if ":" in self.host else self.host

    @property
    def has_auth(self) -> bool:
        return bool(self.username)

    def url(self, scheme: Optional[str] = None) -> str:
        auth = ""
        if self.username:
            auth = quote(self.username, safe="")
            if self.password is not None:
                auth += ":" + quote(self.password, safe="")
            auth += "@"
        return f"{scheme or self.scheme}://{auth}{self._host_part}:{self.port}"

    def format(self, fmt: str = "url") -> str:
        h, p, u, w = self._host_part, self.port, self.username or "", self.password or ""
        if fmt == "url":
            return self.url()
        if fmt == "host:port":
            return f"{h}:{p}"
        if not self.username:
            return f"{h}:{p}"
        if fmt == "host:port:user:pass":
            return f"{h}:{p}:{u}:{w}"
        if fmt == "user:pass@host:port":
            return f"{u}:{w}@{h}:{p}"
        if fmt == "user:pass:host:port":
            return f"{u}:{w}:{h}:{p}"
        raise ValueError(f"unknown format {fmt!r}; choose from {FORMATS}")

    def masked(self) -> str:
        return f"{self.scheme}://{'***@' if self.username else ''}{self._host_part}:{self.port}"

    def __str__(self) -> str:
        return self.url()

    def __repr__(self) -> str:
        return f"Proxy({self.masked()})"

    # client adapters ------------------------------------------------------
    def requests_dict(self) -> dict[str, str]:
        u = self.url()
        return {"http": u, "https": u}

    def httpx_url(self) -> str:
        return self.url()

    def aiohttp_kwargs(self) -> dict[str, str]:
        """aiohttp only supports http proxies natively (use aiohttp_socks for socks)."""
        return {"proxy": self.url()}

    def playwright(self) -> dict[str, str]:
        d = {"server": f"{self.scheme}://{self._host_part}:{self.port}"}
        if self.username:
            d["username"] = self.username
            d["password"] = self.password or ""
        return d

    def curl_args(self) -> list[str]:
        args = ["--proxy", f"{self.scheme}://{self._host_part}:{self.port}"]
        if self.username:
            args += ["--proxy-user", f"{self.username}:{self.password or ''}"]
        return args

    def chrome_arg(self) -> str:
        """Chrome flag. Chrome ignores credentials here; use an auth extension or Playwright."""
        return f"--proxy-server={self.scheme}://{self._host_part}:{self.port}"

    def chrome_extension(self, dest: Union[str, os.PathLike], **kw: Any) -> str:
        """Write a Chrome extension that routes the browser through this proxy.

        See :func:`build_chrome_extension`.
        """
        return build_chrome_extension(self, dest, **kw)

    # stats ----------------------------------------------------------------
    @property
    def banned(self) -> bool:
        return time.time() < self.banned_until

    def record(self, res: CheckResult) -> None:
        self.last_checked = time.time()
        if res.ok:
            self.successes += 1
            self.consecutive_failures = 0
            self.exit_ip = res.ip or self.exit_ip
            self._add_latency(res.latency_ms)
        else:
            self.failures += 1
            self.consecutive_failures += 1

    def _add_latency(self, ms: Optional[float]) -> None:
        if ms is None:
            return
        self.latency_ms = ms if self.latency_ms is None else 0.7 * self.latency_ms + 0.3 * ms

    def to_dict(self, include_password: bool = True) -> dict[str, Any]:
        g = self.geo
        d: dict[str, Any] = {
            "url": self.url() if include_password else self.masked(),
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password if include_password else None,
            "latency_ms": None if self.latency_ms is None else round(self.latency_ms, 1),
            "exit_ip": self.exit_ip,
            "kind": self.kind,
            "isp": self.isp,
            "asn": self.asn,
            "country": self.country,
            "city": g.city if g else None,
            "region": g.region if g else None,
            "latitude": g.latitude if g else None,
            "longitude": g.longitude if g else None,
            "timezone": g.timezone if g else None,
            "locale": g.locale if g else None,
            "accept_language": g.accept_language if g else None,
            "successes": self.successes,
            "failures": self.failures,
        }
        return d


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_\-]*[A-Za-z0-9_])?"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_\-]*[A-Za-z0-9_])?)*$"
)


def _split_colon(s: str) -> list[str]:
    """Split on ':' but not inside [ipv6] brackets."""
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in s:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == ":" and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def _is_port(s: str) -> bool:
    return s.isdigit() and 0 < int(s) <= 65535


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


def _is_host(s: str) -> bool:
    if not s:
        return False
    if s.startswith("["):
        return s.endswith("]") and _is_ip(s) and ":" in s
    if _is_ip(s):
        return True
    if s.isdigit():
        return False
    return bool(_HOSTNAME_RE.match(s))


def _hostport(s: str) -> Optional[tuple[str, int]]:
    parts = _split_colon(s)
    if len(parts) != 2:
        return None
    h, p = parts
    if _is_host(h) and _is_port(p):
        return h.strip("[]"), int(p)
    return None


def parse(line: str, default_scheme: str = "http") -> Proxy:
    """Parse one proxy string. Raises ProxyParseError."""
    raw = line.strip()
    if not raw:
        raise ProxyParseError("empty line")
    scheme = default_scheme.lower()
    m = _SCHEME_RE.match(raw)
    if m:
        scheme = m.group(1).lower()
        raw = raw[m.end() :]
        if scheme not in SCHEMES:
            raise ProxyParseError(f"unsupported scheme {scheme!r}")
    raw = raw.rstrip("/")

    user = pwd = None
    if "@" in raw:
        left, right = raw.rsplit("@", 1)
        lhp, rhp = _hostport(left), _hostport(right)
        # if both halves look like host:port (1.2.3.4:80@bob:1234) prefer the one with an IP
        use_left = (
            (_is_ip(lhp[0]) and not _is_ip(rhp[0])) if lhp and rhp else (bool(lhp) and not rhp)
        )
        hp, cred = (lhp, right) if use_left else (rhp, left)
        if not hp:
            raise ProxyParseError("no valid host:port found")
        host, port = hp
        if ":" in cred:
            user, pwd = cred.split(":", 1)
        else:
            user = cred
        user = unquote(user) or None
        pwd = unquote(pwd) if pwd is not None else None
    else:
        parts = _split_colon(raw)
        if len(parts) == 2:
            hp = _hostport(raw)
            if not hp:
                raise ProxyParseError("invalid host or port")
            host, port = hp
        elif len(parts) == 4:
            a = _is_host(parts[0]) and _is_port(parts[1])  # host:port:user:pass
            b = _is_host(parts[2]) and _is_port(parts[3])  # user:pass:host:port
            if a and b:
                a = _is_ip(parts[0]) or not _is_ip(parts[2])
                b = not a
            if a:
                host, port = parts[0].strip("[]"), int(parts[1])
                user, pwd = parts[2] or None, parts[3]
            elif b:
                host, port = parts[2].strip("[]"), int(parts[3])
                user, pwd = parts[0] or None, parts[1]
            else:
                raise ProxyParseError("could not tell host/port from credentials")
        else:
            raise ProxyParseError("unrecognised format")
    return Proxy(host=host.lower(), port=port, scheme=scheme, username=user, password=pwd)


@dataclass
class ParseResult:
    proxies: list[Proxy]
    errors: list[tuple[int, str, str]]  # (line number, text, reason)
    duplicates: int = 0

    def __iter__(self) -> Iterator[Proxy]:
        return iter(self.proxies)

    def __len__(self) -> int:
        return len(self.proxies)


def parse_many(
    text: str | Iterable[str], default_scheme: str = "http", dedupe: bool = True
) -> ParseResult:
    """Parse many proxies (one or more whitespace-separated per line; # and // comments)."""
    lines = text.splitlines() if isinstance(text, str) else list(text)
    out: list[Proxy] = []
    errs: list[tuple[int, str, str]] = []
    seen: set = set()
    dups = 0
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        for token in line.split():
            try:
                p = parse(token, default_scheme)
            except ProxyParseError as e:
                errs.append((n, token, str(e)))
                continue
            if dedupe:
                if p.key in seen:
                    dups += 1
                    continue
                seen.add(p.key)
            out.append(p)
    return ParseResult(out, errs, dups)


_EXTRACT_RE = re.compile(
    r"(?:(?P<scheme>https?|socks4a?|socks5h?)://)?"
    r"(?:(?P<auth>[^\s:@/<>\"']+:[^\s@/<>\"']+)@)?"
    r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\])"
    r"\s*:\s*(?P<port>\d{2,5})\b",
    re.I,
)


def extract(text: str, default_scheme: str = "http") -> list[Proxy]:
    """Pull ip:port style proxies out of arbitrary text or HTML."""
    found, seen = [], set()
    flat = re.sub(r"</?t[dr][^>]*>|<[^>]+>", " ", text)  # crude: table cells -> spaces
    for src in (text, flat):
        for m in _EXTRACT_RE.finditer(src):
            host, port = m.group("host"), int(m.group("port"))
            if not _is_port(str(port)) or not _is_host(host):
                continue
            user = pwd = None
            if m.group("auth"):
                user, pwd = m.group("auth").split(":", 1)
            p = Proxy(
                host.strip("[]"), port, (m.group("scheme") or default_scheme).lower(), user, pwd
            )
            if p.key not in seen:
                seen.add(p.key)
                found.append(p)
    # HTML tables: <td>1.2.3.4</td><td>8080</td> flattens to "1.2.3.4 8080"
    if re.search(r"<t[dr]\b", text, re.I):
        for m in re.finditer(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})\s+(\d{2,5})(?![\d.])", flat):
            if _is_ip(m.group(1)) and _is_port(m.group(2)):
                p = Proxy(m.group(1), int(m.group(2)), default_scheme.lower())
                if p.key not in seen:
                    seen.add(p.key)
                    found.append(p)
    return found


def load_file(path: str, default_scheme: str = "http") -> ParseResult:
    with open(path, encoding="utf-8", errors="ignore") as f:
        return parse_many(f.read(), default_scheme)


def load_url(
    url: str, default_scheme: str = "http", timeout: float = 20.0, max_bytes: int = 20_000_000
) -> ParseResult:
    """Download a proxy list (http/https only, size-capped).

    Falls back to regex extraction if the text doesn't parse as one proxy per line.
    """
    import requests

    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("only http:// and https:// URLs are supported")
    chunks: list[bytes] = []
    size = 0
    with requests.get(url, timeout=timeout, headers={"User-Agent": _UA}, stream=True) as r:
        r.raise_for_status()
        for chunk in r.iter_content(65536):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"response larger than {max_bytes} bytes")
            chunks.append(chunk)
        encoding = r.encoding or "utf-8"
    text = b"".join(chunks).decode(encoding, errors="ignore")
    res = parse_many(text, default_scheme)
    if not res.proxies:
        res = ParseResult(extract(text, default_scheme), [])
    return res


# --------------------------------------------------------------------------
# Checking
# --------------------------------------------------------------------------
@dataclass
class CheckResult:
    proxy: Proxy
    ok: bool
    latency_ms: Optional[float] = None
    ip: Optional[str] = None
    error: Optional[str] = None
    status: Optional[int] = None


_IP_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z:.])"
    r"(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})"
    r"(?![0-9A-Za-z:])"
)


def _valid_ip(s: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(s.strip())
    except ValueError:
        return None
    return None if ip.is_unspecified else str(ip)


def _extract_ip(text: str) -> Optional[str]:
    """Find the exit IP in a check response (JSON {"ip": ...} or plain text)."""
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        for k in ("ip", "origin", "query", "address"):
            if k in data:
                ip = _valid_ip(str(data[k]).split(",")[0])
                if ip:
                    return ip
    for m in _IP_CANDIDATE_RE.finditer(text[:4096]):
        if m.group(0).count(":") == 2:  # "a::b" in prose (C++ scopes etc.), not a real exit IP
            continue
        ip = _valid_ip(m.group(0))
        if ip:
            return ip
    return None


def _scrub(msg: str, proxy: Proxy) -> str:
    for secret in (proxy.password, proxy.username):
        if secret:
            msg = msg.replace(secret, "***").replace(quote(secret, safe=""), "***")
    return msg[:160]


def check_proxy(
    proxy: Proxy, url: str = DEFAULT_CHECK_URL, timeout: float = 8.0, verify: bool = True
) -> CheckResult:
    """Make one request through the proxy and record the outcome on it."""
    import requests

    t0 = time.perf_counter()
    try:
        r = requests.get(
            url,
            proxies=proxy.requests_dict(),
            timeout=timeout,
            verify=verify,
            headers={"User-Agent": _UA},
        )
        ms = (time.perf_counter() - t0) * 1000
        if r.status_code == 200:
            res = CheckResult(proxy, True, ms, _extract_ip(r.text), None, 200)
        else:
            res = CheckResult(proxy, False, ms, None, f"HTTP {r.status_code}", r.status_code)
    except Exception as e:
        res = CheckResult(proxy, False, None, None, _scrub(f"{type(e).__name__}: {e}", proxy))
    proxy.record(res)
    log.debug("check %s -> %s", proxy.masked(), "ok" if res.ok else res.error)
    return res


def check_many(
    proxies: Iterable[Proxy],
    url: str = DEFAULT_CHECK_URL,
    timeout: float = 8.0,
    workers: int = 50,
    verify: bool = True,
    progress: Optional[Callable[[int, int, CheckResult], None]] = None,
) -> list[CheckResult]:
    """Threaded checker. `progress(done, total, result)` is called as results arrive."""
    plist = list(proxies)
    results: list[CheckResult] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = [ex.submit(check_proxy, p, url, timeout, verify) for p in plist]
        for i, f in enumerate(as_completed(futs), 1):
            r = f.result()
            results.append(r)
            if progress:
                progress(i, len(plist), r)
    return results


def _httpx_client(proxy_url: str, timeout: float, verify: bool = True) -> Any:
    """httpx.AsyncClient routed through one proxy (handles the httpx 0.26 kwarg rename)."""
    import httpx

    try:
        return httpx.AsyncClient(proxy=proxy_url, timeout=timeout, verify=verify)
    except TypeError:  # httpx < 0.26 called it `proxies`
        legacy: dict[str, Any] = {"proxies": proxy_url}
        return httpx.AsyncClient(timeout=timeout, verify=verify, **legacy)


async def acheck_many(
    proxies: Iterable[Proxy],
    url: str = DEFAULT_CHECK_URL,
    timeout: float = 8.0,
    concurrency: int = 200,
    verify: bool = True,
    progress: Optional[Callable[[int, int, CheckResult], None]] = None,
) -> list[CheckResult]:
    """asyncio checker built on httpx (pip install httpx[socks])."""
    import asyncio

    plist = list(proxies)
    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def one(p: Proxy) -> CheckResult:
        nonlocal done
        async with sem:
            t0 = time.perf_counter()
            try:
                async with _httpx_client(p.httpx_url(), timeout, verify) as client:
                    r = await client.get(url, headers={"User-Agent": _UA})
                ms = (time.perf_counter() - t0) * 1000
                if r.status_code == 200:
                    res = CheckResult(p, True, ms, _extract_ip(r.text), None, 200)
                else:
                    res = CheckResult(p, False, ms, None, f"HTTP {r.status_code}", r.status_code)
            except Exception as e:
                res = CheckResult(p, False, None, None, _scrub(f"{type(e).__name__}: {e}", p))
            p.record(res)
            done += 1
            if progress:
                progress(done, len(plist), res)
            return res

    return list(await asyncio.gather(*(one(p) for p in plist)))


def detect_scheme(
    proxy: Proxy,
    schemes: Iterable[str] = ("http", "socks5", "socks4"),
    url: str = DEFAULT_CHECK_URL,
    timeout: float = 8.0,
) -> Optional[Proxy]:
    """Try each scheme and return a working copy of the proxy (or None)."""
    for s in schemes:
        cand = Proxy(proxy.host, proxy.port, s, proxy.username, proxy.password)
        if check_proxy(cand, url, timeout).ok:
            return cand
    return None


# --------------------------------------------------------------------------
# IP classification: residential / datacenter / mobile
# --------------------------------------------------------------------------
# Uses ip-api.com (free tier: HTTP only, ~45 req/min, non-commercial; pass
# api_key for the paid HTTPS endpoint). Signals combined:
#   * ip-api `hosting` / `mobile` flags
#   * ISP / ASN name vs. a list of hosting providers
#   * reverse-DNS hostname (dynamic-pool style vs. server style)
#   * optional rotation sampling: does the exit IP change between connections?
# This is a heuristic with a confidence score, not proof. Static "ISP proxies"
# hosted in datacenters but registered under an ISP ASN will look residential.
# Privacy: lookups send exit IPs to ip-api.com (plain HTTP on the free tier).

_HOSTING_RE = re.compile(
    r"amazon|\baws\b|google (cloud|llc)|microsoft|azure|digitalocean|\bovh|hetzner|linode|"
    r"akamai|vultr|choopa|contabo|leaseweb|\bm247\b|datacamp|cloudflare|oracle|alibaba|"
    r"tencent|scaleway|upcloud|colocrossing|quadranet|hostinger|hosting|datacenter|"
    r"data center|\bvps\b|\bcloud\b|\bcolo\b|dedicated|psychz|zenlayer|ipxo|serverius|"
    r"worldstream|selectel|aeza|frantech|buyvm|ramnode|ionos|godaddy|namecheap|rackspace|"
    r"softlayer|kamatera|netcup|gcore|hivelocity|servers\.com|nforce|sharktech|cdn77|"
    r"fastly|stackpath|zenlayer|bandwidth\.com|packethub|path\.net|terrahost",
    re.I,
)
_CONSUMER_RDNS = re.compile(
    r"dyn|dynamic|dsl|adsl|cable|cpe|pool|dhcp|ppp|customer|subscriber|broadband|"
    r"residential|client|wlan|fiber|ftth|lte|mobile|\d+[-.]\d+[-.]\d+[-.]\d+",
    re.I,
)
_SERVER_RDNS = re.compile(
    r"compute|amazonaws|googleusercontent|\bvps|server|hosting|cloud|\bec2|vultr|linode|"
    r"\bovh|hetzner|digitalocean|colo|dedicated|\bnode\d",
    re.I,
)


class _RateLimiter:
    def __init__(self, per_minute: float):
        self.interval = 60.0 / per_minute
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            t = max(now, self._next)
            self._next = t + self.interval
        if t > now:
            time.sleep(t - now)


_IPAPI_LIMIT = _RateLimiter(40)  # stay under the free 45/min cap
_IP_CACHE: dict[str, dict[str, Any]] = {}


def lookup_ip(
    ip: str, timeout: float = 8.0, api_key: Optional[str] = None, base_url: Optional[str] = None
) -> dict[str, Any]:
    """Look up ISP/ASN/hosting flags and geolocation for an IP (cached, rate limited)."""
    import requests

    if ip in _IP_CACHE:
        return _IP_CACHE[ip]
    base = base_url or ("https://pro.ip-api.com" if api_key else "http://ip-api.com")
    params = {
        "fields": (
            "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,offset,"
            "currency,isp,org,as,mobile,proxy,hosting,query"
        )
    }
    if api_key:
        params["key"] = api_key
    data, r = None, None
    for _ in range(3):
        _IPAPI_LIMIT.wait()
        r = requests.get(f"{base}/json/{ip}", params=params, timeout=timeout)
        if r.status_code == 429:
            time.sleep(int(r.headers.get("X-Ttl", "5")) + 1)
            continue
        data = r.json()
        break
    if data is None:
        raise RuntimeError("ip-api rate limit hit; slow down or pass api_key")
    if data.get("status") != "success":
        raise RuntimeError(data.get("message", "lookup failed"))
    if r is not None and r.headers.get("X-Rl") == "0":  # window exhausted
        time.sleep(int(r.headers.get("X-Ttl", "1")) + 1)
    result: dict[str, Any] = dict(data)
    _IP_CACHE[ip] = result
    return result


def reverse_dns(ip: str, timeout: float = 2.0) -> Optional[str]:
    """PTR lookup with a hard timeout (the resolver itself has none)."""
    box: list[str] = []

    def work() -> None:
        try:
            box.append(socket.gethostbyaddr(ip)[0])
        except (OSError, UnicodeError):
            pass

    t = threading.Thread(target=work, daemon=True)  # daemon: never blocks interpreter exit
    t.start()
    t.join(timeout)
    return box[0] if box else None


@dataclass
class Classification:
    ip: Optional[str]
    kind: str  # residential | datacenter | mobile | unknown
    confidence: float
    isp: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    hostname: Optional[str] = None
    known_proxy: bool = False  # listed as a proxy in ip-api's database
    rotates: Optional[bool] = None  # None = not sampled
    unique_ips: int = 0
    reasons: list[str] = field(default_factory=list)


def classify_ip(
    ip: str,
    api_key: Optional[str] = None,
    use_rdns: bool = True,
    timeout: float = 8.0,
    base_url: Optional[str] = None,
) -> Classification:
    info = lookup_ip(ip, timeout, api_key, base_url)
    isp = info.get("isp") or info.get("org")
    names = f"{info.get('isp', '')} {info.get('org', '')} {info.get('as', '')}"
    asn = (info.get("as") or "").split(" ")[0] or None
    host = reverse_dns(ip) if use_rdns else None
    reasons: list[str] = []
    if info.get("hosting"):
        kind, conf = "datacenter", 0.9
        reasons.append("flagged as hosting by ip-api")
    elif _HOSTING_RE.search(names):
        kind, conf = "datacenter", 0.8
        reasons.append(f"ISP/ASN looks like a hosting provider ({isp})")
    elif info.get("mobile"):
        kind, conf = "mobile", 0.85
        reasons.append("mobile carrier ASN")
    else:
        kind, conf = "residential", 0.6
        reasons.append(f"consumer-looking ISP ({isp})")
        if host and _SERVER_RDNS.search(host):
            kind, conf = "datacenter", 0.65
            reasons.append(f"reverse DNS looks like a server ({host})")
        elif host and _CONSUMER_RDNS.search(host):
            conf = 0.8
            reasons.append(f"reverse DNS looks like a consumer line ({host})")
        elif host:
            reasons.append(f"reverse DNS is neutral ({host})")
        else:
            conf = 0.55
            reasons.append("no reverse DNS")
    known = bool(info.get("proxy"))
    if known:
        if kind == "datacenter":
            conf = min(0.97, conf + 0.05)
        note = "" if kind == "datacenter" else " (normal for commercial residential pools)"
        reasons.append("IP is listed in proxy databases" + note)
    return Classification(
        ip, kind, round(conf, 2), isp, asn, info.get("countryCode"), host, known, None, 1, reasons
    )


def classify(
    proxy: Proxy,
    rotation_samples: int = 0,
    check_url: str = DEFAULT_CHECK_URL,
    timeout: float = 8.0,
    api_key: Optional[str] = None,
    use_rdns: bool = True,
    delay: float = 0.0,
    max_ips: int = 4,
    base_url: Optional[str] = None,
) -> Classification:
    """
    Classify a proxy's exit IP. With rotation_samples=N, makes N extra requests
    through the proxy to see whether the exit IP rotates (typical of residential
    pools) and classifies up to `max_ips` distinct IPs, taking the majority.
    Each distinct IP costs one ip-api lookup (cached), so keep N small on the free tier.
    """
    ips: list[str] = [proxy.exit_ip] if proxy.exit_ip else []
    if not ips:
        res = check_proxy(proxy, check_url, timeout)
        if not (res.ok and res.ip):
            c = Classification(None, "unknown", 0.0, reasons=[res.error or "no exit IP"])
            proxy.kind = c.kind
            return c
        ips.append(res.ip)
    for _ in range(max(0, rotation_samples)):
        if delay:
            time.sleep(delay)
        res = check_proxy(proxy, check_url, timeout)
        if res.ok and res.ip:
            ips.append(res.ip)
    unique = list(dict.fromkeys(ips))
    results = []
    for ip in unique[:max_ips]:
        try:
            results.append(classify_ip(ip, api_key, use_rdns, timeout, base_url))
        except Exception as e:
            results.append(Classification(ip, "unknown", 0.0, reasons=[f"lookup failed: {e}"]))
    known = [c for c in results if c.kind != "unknown"]
    if not known:
        c = results[0]
    else:
        votes: dict[str, int] = {}
        for item in known:
            votes[item.kind] = votes.get(item.kind, 0) + 1
        top = max(votes, key=lambda k: votes[k])
        c = next(x for x in known if x.kind == top)
        c.confidence = round(c.confidence * (0.5 + 0.5 * votes[top] / len(known)), 2)
    c.unique_ips = len(unique)
    if rotation_samples:
        c.rotates = len(unique) > 1
        if c.rotates and c.kind == "residential":
            asns = {x.asn for x in known}
            c.confidence = round(min(0.95, c.confidence + 0.1 + (0.05 if len(asns) > 1 else 0)), 2)
            c.reasons.append(
                f"exit IP rotated across {len(unique)} addresses"
                + (f" on {len(asns)} different networks" if len(asns) > 1 else "")
            )
        elif c.rotates:
            c.reasons.append(f"rotates across {len(unique)} IPs but on hosting networks")
        elif rotation_samples >= 3 and c.kind == "residential":
            c.reasons.append("same IP on every sample: sticky session or static ISP proxy")
    proxy.kind, proxy.isp, proxy.asn, proxy.country = c.kind, c.isp, c.asn, c.country
    proxy.exit_ip = proxy.exit_ip or c.ip
    return c


def classify_many(
    proxies: Iterable[Proxy],
    workers: int = 20,
    progress: Optional[Callable[[int, int], None]] = None,
    **kw: Any,
) -> list[tuple[Proxy, Classification]]:
    """Threaded classify(); lookups are globally rate limited to the free ip-api cap."""
    plist = list(proxies)
    out: list[tuple[Proxy, Classification]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(classify, p, **kw): p for p in plist}
        for i, f in enumerate(as_completed(futs), 1):
            out.append((futs[f], f.result()))
            if progress:
                progress(i, len(plist))
    return out


# --------------------------------------------------------------------------
# Geolocation: coordinates, timezone, locale and Accept-Language for an exit IP
# --------------------------------------------------------------------------
# Same ip-api.com lookup (and cache and rate limit) as classification. IP geolocation is
# city-level at best and the provider reports no accuracy radius. The locale and
# Accept-Language values are *inferred from the country*: an IP address cannot reveal
# what language a user actually speaks.
DEFAULT_LOCALE = "en-US"
_COUNTRY_LOCALE_TABLE = """
US:en-US CA:en-CA MX:es-MX BR:pt-BR AR:es-AR CL:es-CL CO:es-CO PE:es-PE VE:es-VE
EC:es-EC UY:es-UY PY:es-PY BO:es-BO CR:es-CR PA:es-PA DO:es-DO GT:es-GT SV:es-SV
HN:es-HN NI:es-NI CU:es-CU PR:es-PR JM:en-JM TT:en-TT BB:en-BB BS:en-BS HT:fr-HT
GB:en-GB IE:en-IE FR:fr-FR DE:de-DE AT:de-AT CH:de-CH ES:es-ES PT:pt-PT IT:it-IT
NL:nl-NL BE:nl-BE LU:fr-LU DK:da-DK SE:sv-SE NO:nb-NO FI:fi-FI IS:is-IS PL:pl-PL
CZ:cs-CZ SK:sk-SK HU:hu-HU RO:ro-RO BG:bg-BG GR:el-GR HR:hr-HR RS:sr-RS SI:sl-SI
UA:uk-UA RU:ru-RU BY:be-BY LT:lt-LT LV:lv-LV EE:et-EE TR:tr-TR IL:he-IL SA:ar-SA
AE:ar-AE EG:ar-EG MA:ar-MA DZ:ar-DZ TN:ar-TN QA:ar-QA KW:ar-KW IQ:ar-IQ JO:ar-JO
LB:ar-LB IR:fa-IR PK:ur-PK IN:en-IN BD:bn-BD LK:si-LK NP:ne-NP CN:zh-CN HK:zh-HK
TW:zh-TW JP:ja-JP KR:ko-KR TH:th-TH VN:vi-VN ID:id-ID MY:ms-MY SG:en-SG PH:en-PH
AU:en-AU NZ:en-NZ ZA:en-ZA NG:en-NG KE:en-KE GH:en-GH ET:am-ET TZ:sw-TZ UG:en-UG
KZ:ru-KZ UZ:uz-UZ GE:ka-GE AM:hy-AM AZ:az-AZ
"""
_COUNTRY_LOCALES: dict[str, str] = dict(item.split(":") for item in _COUNTRY_LOCALE_TABLE.split())


def locale_for_country(country_code: Optional[str]) -> tuple[str, bool]:
    """Most common browser locale for a country. Returns ``(locale, found)``.

    ``found`` is False when the country is not in the built-in table, in which case the
    locale is ``DEFAULT_LOCALE``.
    """
    loc = _COUNTRY_LOCALES.get((country_code or "").upper())
    return (loc, True) if loc else (DEFAULT_LOCALE, False)


def _accept_language(locale: str) -> str:
    """Browser-style header for a locale: ``es-MX`` -> ``es-MX,es;q=0.9,en;q=0.8``."""
    lang = locale.split("-")[0]
    parts = [locale]
    if lang != locale:
        parts.append(f"{lang};q=0.9")
    if lang != "en":
        parts.append("en;q=0.8")
    return ",".join(parts)


def _float_or_none(value: Any) -> Optional[float]:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


@dataclass
class Geo:
    """Where an exit IP appears to be, plus browser settings that match it."""

    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    zip: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None  # IANA name, e.g. "America/Jamaica"
    utc_offset: Optional[int] = None  # seconds east of UTC right now (DST aware)
    currency: Optional[str] = None
    locale: str = DEFAULT_LOCALE  # inferred from the country, see locale_for_country()
    locale_fallback: bool = False  # True: country not in the table, default locale used
    accept_language: str = "en-US,en;q=0.9"

    def headers(self) -> dict[str, str]:
        """Headers to send so requests look consistent with the exit location."""
        return {"Accept-Language": self.accept_language}

    def geolocation(self, accuracy: float = 100.0) -> dict[str, float]:
        """``{"latitude", "longitude", "accuracy"}`` as the browser Geolocation API wants it.

        ``accuracy`` (metres) is a value *you* choose to report: IP lookups do not provide
        one, and the real error is typically kilometres (city level).
        """
        if self.latitude is None or self.longitude is None:
            raise ValueError("no coordinates available for this IP")
        return {"latitude": self.latitude, "longitude": self.longitude, "accuracy": accuracy}

    def playwright_context(
        self, accuracy: float = 100.0, grant_geolocation: bool = True, include_header: bool = True
    ) -> dict[str, Any]:
        """Keyword arguments for ``browser.new_context(**geo.playwright_context())``."""
        ctx: dict[str, Any] = {"locale": self.locale}
        if self.timezone:
            ctx["timezone_id"] = self.timezone
        if self.latitude is not None and self.longitude is not None:
            ctx["geolocation"] = self.geolocation(accuracy)
            if grant_geolocation:
                ctx["permissions"] = ["geolocation"]
        if include_header:
            ctx["extra_http_headers"] = self.headers()
        return ctx

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def geolocate_ip(
    ip: str, api_key: Optional[str] = None, timeout: float = 8.0, base_url: Optional[str] = None
) -> Geo:
    """Geolocate an IP address (cached, shared rate limit with classification)."""
    info = lookup_ip(ip, timeout, api_key, base_url)
    cc = info.get("countryCode")
    locale, found = locale_for_country(cc)
    offset = _float_or_none(info.get("offset"))
    return Geo(
        ip=ip,
        country=info.get("country"),
        country_code=cc,
        region=info.get("regionName"),
        city=info.get("city"),
        zip=info.get("zip") or None,
        latitude=_float_or_none(info.get("lat")),
        longitude=_float_or_none(info.get("lon")),
        timezone=info.get("timezone") or None,
        utc_offset=None if offset is None else int(offset),
        currency=info.get("currency") or None,
        locale=locale,
        locale_fallback=not found,
        accept_language=_accept_language(locale),
    )


def geolocate(
    proxy: Proxy,
    check_url: str = DEFAULT_CHECK_URL,
    timeout: float = 8.0,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    refresh: bool = False,
) -> Geo:
    """Find where a proxy's exit IP is. Stores the result on ``proxy.geo`` and returns it.

    Uses the exit IP recorded by an earlier check when there is one; pass ``refresh=True``
    to make a fresh request first. That matters for *rotating* proxies, where the next
    connection may leave from a different place: the result describes one exit IP only.
    Raises ``LookupError`` if the proxy gives no exit IP, ``RuntimeError`` if ip-api fails.
    """
    ip = None if refresh else proxy.exit_ip
    if not ip:
        res = check_proxy(proxy, check_url, timeout)
        if not (res.ok and res.ip):
            raise LookupError(res.error or "proxy returned no exit IP")
        ip = res.ip
    geo = geolocate_ip(ip, api_key, timeout, base_url)
    proxy.geo = geo
    return geo


def geolocate_many(
    proxies: Iterable[Proxy],
    workers: int = 20,
    progress: Optional[Callable[[int, int], None]] = None,
    **kw: Any,
) -> list[tuple[Proxy, Optional[Geo]]]:
    """Threaded geolocate(). A proxy that fails gets ``None`` instead of raising."""
    plist = list(proxies)

    def one(p: Proxy) -> Optional[Geo]:
        try:
            return geolocate(p, **kw)
        except Exception as e:
            log.debug("geolocate %s failed: %s", p.masked(), _scrub(f"{type(e).__name__}: {e}", p))
            return None

    out: list[tuple[Proxy, Optional[Geo]]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(one, p): p for p in plist}
        for i, f in enumerate(as_completed(futs), 1):
            out.append((futs[f], f.result()))
            if progress:
                progress(i, len(plist))
    return out


# --------------------------------------------------------------------------
# Rotating pool
# --------------------------------------------------------------------------
class ProxyPool:
    """
    Thread-safe rotating pool with failure tracking.

    strategy: round_robin | random | least_used | fastest | sticky
      sticky  - the same `key` always maps to the same proxy (rendezvous hashing),
                so one account/session keeps one exit IP; falls over if it is banned.
    A proxy is banned after `max_failures` consecutive failures for
    cooldown * 2**bans seconds (capped at max_cooldown).
    """

    STRATEGIES = ("round_robin", "random", "least_used", "fastest", "sticky")

    def __init__(
        self,
        proxies: Iterable[Proxy] = (),
        strategy: str = "round_robin",
        cooldown: float = 60.0,
        max_failures: int = 3,
        max_cooldown: float = 3600.0,
        seed: Optional[int] = None,
    ):
        if strategy not in self.STRATEGIES:
            raise ValueError(f"strategy must be one of {self.STRATEGIES}")
        self.strategy = strategy
        self.cooldown, self.max_failures, self.max_cooldown = cooldown, max_failures, max_cooldown
        self._proxies: list[Proxy] = []
        self._keys: set = set()
        self._i = 0
        self._lock = threading.RLock()
        self._rng = random.Random(seed)
        for p in proxies:
            self.add(p)

    # construction ---------------------------------------------------------
    @classmethod
    def from_text(cls, text: str, **kw: Any) -> ProxyPool:
        scheme = kw.pop("default_scheme", "http")
        return cls(parse_many(text, scheme).proxies, **kw)

    @classmethod
    def from_file(cls, path: str, **kw: Any) -> ProxyPool:
        scheme = kw.pop("default_scheme", "http")
        return cls(load_file(path, scheme).proxies, **kw)

    # container ------------------------------------------------------------
    def add(self, proxy: Proxy | str) -> bool:
        if isinstance(proxy, str):
            proxy = parse(proxy)
        with self._lock:
            if proxy.key in self._keys:
                return False
            self._keys.add(proxy.key)
            self._proxies.append(proxy)
            return True

    def remove(self, proxy: Proxy) -> None:
        with self._lock:
            if proxy.key in self._keys:
                self._keys.discard(proxy.key)
                self._proxies = [p for p in self._proxies if p.key != proxy.key]

    def __len__(self) -> int:
        return len(self._proxies)

    def __iter__(self) -> Iterator[Proxy]:
        return iter(list(self._proxies))

    def available(self) -> list[Proxy]:
        now = time.time()
        with self._lock:
            return [p for p in self._proxies if now >= p.banned_until]

    # selection ------------------------------------------------------------
    def get(self, key: Optional[str] = None) -> Proxy:
        with self._lock:
            avail = self.available()
            if not avail:
                wait = min((p.banned_until for p in self._proxies), default=0) - time.time()
                raise NoProxyAvailable(
                    "pool is empty"
                    if not self._proxies
                    else f"all {len(self._proxies)} proxies banned; "
                    f"next frees in {max(wait, 0):.0f}s"
                )
            s = self.strategy
            if s == "sticky" and key is not None:
                k = str(key).encode()
                p = max(
                    avail, key=lambda x: blake2b(k + repr(x.key).encode(), digest_size=8).digest()
                )
            elif s == "random":
                p = self._rng.choice(avail)
            elif s == "least_used":
                p = min(avail, key=lambda x: x.uses)
            elif s == "fastest":
                # weighted by 1/latency; untested proxies get a fair chance
                known = [x.latency_ms for x in avail if x.latency_ms]
                default = (sum(known) / len(known)) if known else 1000.0
                weights = [1.0 / max(x.latency_ms or default, 1.0) for x in avail]
                p = self._rng.choices(avail, weights=weights, k=1)[0]
            else:  # round_robin (also sticky with no key)
                p = avail[self._i % len(avail)]
                self._i += 1
            p.uses += 1
            return p

    # feedback -------------------------------------------------------------
    def report_success(self, proxy: Proxy, latency_ms: Optional[float] = None) -> None:
        with self._lock:
            proxy.successes += 1
            proxy.consecutive_failures = 0
            proxy._add_latency(latency_ms)

    def report_failure(self, proxy: Proxy) -> None:
        with self._lock:
            proxy.failures += 1
            proxy.consecutive_failures += 1
            if proxy.consecutive_failures >= self.max_failures:
                secs = min(self.cooldown * (2 ** min(proxy.bans, 20)), self.max_cooldown)
                proxy.banned_until = time.time() + secs
                proxy.bans += 1
                proxy.consecutive_failures = 0
                log.info("banned %s for %.0fs (ban #%d)", proxy.masked(), secs, proxy.bans)

    def unban_all(self) -> None:
        with self._lock:
            for p in self._proxies:
                p.banned_until = 0.0

    @contextmanager
    def lease(self, key: Optional[str] = None) -> Iterator[Proxy]:
        """with pool.lease() as proxy: ...  (exception => failure, else success)"""
        p = self.get(key)
        t0 = time.perf_counter()
        try:
            yield p
        except Exception:
            self.report_failure(p)
            raise
        else:
            self.report_success(p, (time.perf_counter() - t0) * 1000)

    # maintenance ----------------------------------------------------------
    def check(self, drop_dead: bool = True, **kw: Any) -> list[CheckResult]:
        """Health-check every proxy; optionally remove the dead ones."""
        results = check_many(list(self._proxies), **kw)
        if drop_dead:
            for r in results:
                if not r.ok:
                    self.remove(r.proxy)
        return results

    def only(self, *kinds: str) -> ProxyPool:
        """New pool with just the proxies of these kinds (after classify())."""
        return ProxyPool(
            [p for p in self._proxies if p.kind in kinds],
            strategy=self.strategy,
            cooldown=self.cooldown,
            max_failures=self.max_failures,
            max_cooldown=self.max_cooldown,
        )

    def classify(self, **kw: Any) -> list[tuple[Proxy, Classification]]:
        return classify_many(list(self._proxies), **kw)

    def geolocate(self, **kw: Any) -> list[tuple[Proxy, Optional[Geo]]]:
        """Fill ``proxy.geo`` (location, timezone, locale) for every proxy in the pool."""
        return geolocate_many(list(self._proxies), **kw)

    def stats(self) -> list[dict]:
        now = time.time()
        rows = []
        for p in self._proxies:
            d = p.to_dict(include_password=False)
            d.update(uses=p.uses, banned=p.banned, banned_for=max(0, round(p.banned_until - now)))
            rows.append(d)
        return rows

    # request helpers ------------------------------------------------------
    def _pick(self, key: Optional[str], tried: set[Any], attempt: int) -> Proxy:
        """Choose a proxy for one attempt, preferring ones not yet tried for this request.

        On retries a sticky key is perturbed so the request fails over instead of
        hammering the same (possibly broken) proxy.
        """
        k = key if (key is None or attempt == 0) else f"{key}#retry{attempt}"
        proxy = self.get(k)
        for _ in range(len(self._proxies)):
            if proxy.key not in tried or len(tried) >= len(self.available()):
                break
            proxy = self.get(k)
        return proxy

    def request(
        self,
        method: str,
        url: str,
        retries: int = 3,
        key: Optional[str] = None,
        retry_statuses: Iterable[int] = (407, 429, 502, 503, 504),
        timeout: float = 15.0,
        **kw: Any,
    ) -> Any:
        """requests.request() through the pool, rotating to another proxy on failure.

        Network errors and ``retry_statuses`` count as proxy failures (and feed the ban
        logic). Malformed-URL errors are raised immediately. Raises PoolExhausted when
        every attempt fails.
        """
        import requests

        statuses = set(retry_statuses)
        attempts = max(1, retries)
        last: Optional[BaseException] = None
        last_proxy: Optional[Proxy] = None
        tried: set[Any] = set()
        for attempt in range(attempts):
            proxy = self._pick(key, tried, attempt)
            tried.add(proxy.key)
            last_proxy = proxy
            t0 = time.perf_counter()
            try:
                r = requests.request(
                    method, url, proxies=proxy.requests_dict(), timeout=timeout, **kw
                )
            except (
                requests.exceptions.InvalidURL,
                requests.exceptions.MissingSchema,
                requests.exceptions.InvalidSchema,
            ):
                raise
            except requests.RequestException as e:
                self.report_failure(proxy)
                last = e
                continue
            if r.status_code in statuses:
                self.report_failure(proxy)
                last = RuntimeError(f"HTTP {r.status_code}")
                continue
            self.report_success(proxy, (time.perf_counter() - t0) * 1000)
            return r
        detail = _scrub(str(last), last_proxy) if last and last_proxy else "n/a"
        raise PoolExhausted(f"{attempts} attempts failed; last error: {detail}") from last

    def http_get(self, url: str, **kw: Any) -> Any:  # pool.get() is proxy selection
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> Any:
        return self.request("POST", url, **kw)

    def session(self, key: Optional[str] = None) -> Any:
        """A requests.Session pinned to one proxy from the pool (``session.proxy`` is the Proxy)."""
        import requests

        s = requests.Session()
        p = self.get(key)
        s.proxies.update(p.requests_dict())
        s.proxy = p  # type: ignore[attr-defined]
        return s

    async def arequest(
        self,
        method: str,
        url: str,
        retries: int = 3,
        key: Optional[str] = None,
        retry_statuses: Iterable[int] = (407, 429, 502, 503, 504),
        timeout: float = 15.0,
        **kw: Any,
    ) -> Any:
        """httpx async version of request()."""
        import httpx

        statuses = set(retry_statuses)
        attempts = max(1, retries)
        last: Optional[BaseException] = None
        last_proxy: Optional[Proxy] = None
        tried: set[Any] = set()
        for attempt in range(attempts):
            proxy = self._pick(key, tried, attempt)
            tried.add(proxy.key)
            last_proxy = proxy
            t0 = time.perf_counter()
            try:
                async with _httpx_client(proxy.httpx_url(), timeout) as client:
                    r = await client.request(method, url, **kw)
            except (httpx.InvalidURL, httpx.UnsupportedProtocol):
                raise
            except httpx.HTTPError as e:
                self.report_failure(proxy)
                last = e
                continue
            if r.status_code in statuses:
                self.report_failure(proxy)
                last = RuntimeError(f"HTTP {r.status_code}")
                continue
            self.report_success(proxy, (time.perf_counter() - t0) * 1000)
            return r
        detail = _scrub(str(last), last_proxy) if last and last_proxy else "n/a"
        raise PoolExhausted(f"{attempts} attempts failed; last error: {detail}") from last


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------
def export_txt(proxies: Iterable[Proxy], fmt: str = "url") -> str:
    return "\n".join(p.format(fmt) for p in proxies) + "\n"


def export_json(proxies: Iterable[Proxy], include_password: bool = True) -> str:
    return json.dumps([p.to_dict(include_password) for p in proxies], indent=2)


def export_csv(proxies: Iterable[Proxy], include_password: bool = True) -> str:
    buf = io.StringIO()
    cols = [
        "scheme",
        "host",
        "port",
        "username",
        "password",
        "latency_ms",
        "exit_ip",
        "kind",
        "isp",
        "asn",
        "country",
        "city",
        "region",
        "latitude",
        "longitude",
        "timezone",
        "locale",
    ]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for p in proxies:
        w.writerow(p.to_dict(include_password))
    return buf.getvalue()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _one_line(e: BaseException) -> str:
    return " ".join(str(e).split())[:200]


def _load_any(src: str, scheme: str) -> ParseResult:
    if src.startswith(("http://", "https://")):
        return load_url(src, scheme)
    if src == "-":
        return parse_many(sys.stdin.read(), scheme)
    return load_file(src, scheme)


def _write(out: Optional[str], data: str) -> None:
    if out:
        # lists may contain credentials: create new files readable by the owner only
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
    else:
        sys.stdout.write(data)


# --------------------------------------------------------------------------
# Chrome extension export
# --------------------------------------------------------------------------
_CHROME_SCHEMES = {
    "http": "http",
    "https": "https",
    "socks4": "socks4",
    "socks4a": "socks4",
    "socks5": "socks5",
    "socks5h": "socks5",  # Chrome always resolves DNS through a SOCKS5 proxy
}

_EXT_BACKGROUND_JS = """\
// Generated by proxyforge. Contains proxy credentials in plain text: do not publish.
const PROXY = %(proxy)s;

chrome.proxy.settings.set({
  value: {
    mode: "fixed_servers",
    rules: {
      singleProxy: { scheme: PROXY.scheme, host: PROXY.host, port: PROXY.port },
      bypassList: PROXY.bypass,
    },
  },
  scope: "regular",
});

if (PROXY.username) {
  chrome.webRequest.onAuthRequired.addListener(
    (details, callback) => {
      if (!details.isProxy) return callback({});
      callback({ authCredentials: { username: PROXY.username, password: PROXY.password } });
    },
    { urls: ["<all_urls>"] },
    ["asyncBlocking"]
  );
}
"""


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for fname, text in files.items():
            zi = zipfile.ZipInfo(fname, date_time=(2020, 1, 1, 0, 0, 0))  # reproducible
            zi.external_attr = 0o600 << 16
            z.writestr(zi, text, compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def _pb_field(num: int, data: bytes) -> bytes:
    """Protobuf length-delimited field (wire type 2)."""
    n, varint = len(data), bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        varint.append(b | (0x80 if n else 0))
        if not n:
            break
    tag = (num << 3) | 2
    tag_bytes = bytearray()
    while True:
        b = tag & 0x7F
        tag >>= 7
        tag_bytes.append(b | (0x80 if tag else 0))
        if not tag:
            break
    return bytes(tag_bytes) + bytes(varint) + data


def crx_extension_id(public_key_der: bytes) -> str:
    """Chrome extension ID (32 letters a-p) for a DER SubjectPublicKeyInfo public key."""
    from hashlib import sha256

    return "".join(chr(ord("a") + int(c, 16)) for c in sha256(public_key_der).hexdigest()[:32])


def _write_crx(path: str, zip_data: bytes) -> None:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise ImportError("CRX export needs: pip install proxyforge[crx]") from e
    from hashlib import sha256

    key_path = os.path.splitext(path)[0] + ".pem"
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"{key_path} is not an RSA key")
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    pub = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signed_data = _pb_field(1, sha256(pub).digest()[:16])  # SignedData.crx_id
    to_sign = b"CRX3 SignedData\x00" + struct.pack("<I", len(signed_data)) + signed_data + zip_data
    sig = key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
    proof = _pb_field(1, pub) + _pb_field(2, sig)  # AsymmetricKeyProof
    header = _pb_field(2, proof) + _pb_field(10000, signed_data)  # CrxFileHeader
    with open(path, "wb") as f:
        f.write(b"Cr24" + struct.pack("<II", 3, len(header)) + header + zip_data)


def build_chrome_extension(
    proxy: Proxy,
    dest: Union[str, os.PathLike],
    *,
    name: Optional[str] = None,
    bypass: Iterable[str] = ("localhost", "127.0.0.1", "[::1]"),
) -> str:
    """Export ``proxy`` as a Manifest V3 Chrome extension and return the path written.

    If ``dest`` ends in ``.zip`` a zip archive is written (what Selenium's
    ``options.add_extension`` and the Chrome Web Store take); if it ends in ``.crx`` a signed
    CRX3 package is written (needs ``pip install proxyforge[crx]``; the signing key is kept
    in ``<dest>.pem`` and reused so the extension ID stays the same); otherwise ``dest`` is
    created as an unpacked directory (what ``chrome://extensions`` > *Load unpacked*
    and Playwright's ``--load-extension`` take).

    The extension sets Chrome's proxy and answers the proxy's auth challenge, so
    username/password proxies work without a prompt. The credentials are stored in
    plain text inside the extension. Chrome cannot authenticate to SOCKS proxies,
    so those must not have credentials (``ValueError``).
    """
    scheme = _CHROME_SCHEMES.get(proxy.scheme)
    if scheme is None:
        raise ValueError(f"Chrome cannot use a {proxy.scheme!r} proxy")
    if proxy.has_auth and scheme.startswith("socks"):
        raise ValueError(
            "Chrome does not support username/password for SOCKS proxies; "
            "use an http(s) proxy or a local forwarder"
        )
    cfg = {
        "scheme": scheme,
        "host": proxy.host,
        "port": proxy.port,
        "username": proxy.username or "",
        "password": proxy.password or "",
        "bypass": list(bypass),
    }
    manifest: dict[str, Any] = {
        "manifest_version": 3,
        "name": name or f"proxyforge {proxy.host}:{proxy.port}",
        "version": "1.0.0",
        "description": "Routes Chrome through a single proxy. Generated by proxyforge.",
        "permissions": ["proxy", "webRequest", "webRequestAuthProvider"],
        "host_permissions": ["<all_urls>"],
        "background": {"service_worker": "background.js"},
    }
    files = {
        "manifest.json": json.dumps(manifest, indent=2) + "\n",
        "background.js": _EXT_BACKGROUND_JS % {"proxy": json.dumps(cfg, indent=2)},
    }
    out = os.fspath(dest)
    if out.lower().endswith(".crx"):
        _write_crx(out, _zip_bytes(files))
    elif out.lower().endswith(".zip"):
        with open(out, "wb") as f:
            f.write(_zip_bytes(files))
    else:
        os.makedirs(out, exist_ok=True)
        for fname, text in files.items():
            fd = os.open(os.path.join(out, fname), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
    return out


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point. Returns a process exit code (``check`` returns 1 if nothing works)."""
    doc = (__doc__ or "proxyforge").strip().split("\n\n")[0]
    ap = argparse.ArgumentParser(prog="proxyforge", description=doc)
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument(
        "-v", "--verbose", action="count", default=0, help="log to stderr (-v info, -vv debug)"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("source", help="file path, URL, or - for stdin")
        p.add_argument(
            "--scheme",
            default="http",
            choices=sorted(SCHEMES),
            help="default scheme for entries without one",
        )

    p1 = sub.add_parser("parse", help="parse a list and report errors")
    common(p1)

    p2 = sub.add_parser("convert", help="convert between formats")
    common(p2)
    p2.add_argument("--to", default="url", choices=[*FORMATS, "json", "csv"])
    p2.add_argument("-o", "--out")

    p3 = sub.add_parser("check", help="test proxies, keep the working ones")
    common(p3)
    p3.add_argument("--url", default=DEFAULT_CHECK_URL)
    p3.add_argument("--timeout", type=float, default=8.0)
    p3.add_argument("--workers", type=int, default=100)
    p3.add_argument("--detect", action="store_true", help="try http, socks5, socks4 for each proxy")
    p3.add_argument("--max-latency", type=float, help="drop proxies slower than N ms")
    p3.add_argument(
        "--classify",
        action="store_true",
        help="tag working proxies residential/datacenter/mobile via ip-api.com "
        "(free tier ~40 lookups/min, so big lists take a while)",
    )
    p3.add_argument(
        "--rotation-samples",
        type=int,
        default=0,
        help="extra requests per proxy to see if the exit IP rotates",
    )
    p3.add_argument(
        "--kind",
        nargs="+",
        choices=["residential", "datacenter", "mobile"],
        help="keep only these kinds (implies --classify)",
    )
    p3.add_argument(
        "--geo",
        action="store_true",
        help="look up city, coordinates, timezone and locale of each exit IP (ip-api.com)",
    )
    p3.add_argument("--api-key", help="ip-api.com pro key (https, higher limits)")
    p3.add_argument("--to", default="url", choices=[*FORMATS, "json", "csv"])
    p3.add_argument("-o", "--out")

    p4 = sub.add_parser("extension", help="export one proxy as a Chrome extension")
    p4.add_argument("proxy", help="proxy in any supported format")
    p4.add_argument(
        "-o", "--out", default="proxy-extension.zip", help="*.zip, *.crx or a directory"
    )
    p4.add_argument("--scheme", default="http", choices=sorted(SCHEMES))
    p4.add_argument("--bypass", nargs="*", help="hosts that skip the proxy")

    a = ap.parse_args(argv)
    if a.verbose:
        logging.basicConfig(
            level=logging.DEBUG if a.verbose > 1 else logging.INFO,
            format="%(levelname)s %(name)s: %(message)s",
            stream=sys.stderr,
        )
    if a.cmd == "extension":
        try:
            px = parse(a.proxy, a.scheme)
            kw = {"bypass": a.bypass} if a.bypass is not None else {}
            print(build_chrome_extension(px, a.out, **kw))
        except ValueError as e:
            print(f"error: {_one_line(e)}", file=sys.stderr)
            return 2
        return 0
    try:
        res = _load_any(a.source, a.scheme)
    except (OSError, ValueError) as e:
        print(f"error: could not load {a.source!r}: {_one_line(e)}", file=sys.stderr)
        return 2
    print(
        f"parsed {len(res)} proxies, {res.duplicates} duplicates, {len(res.errors)} errors",
        file=sys.stderr,
    )

    if a.cmd == "parse":
        for n, text, why in res.errors[:50]:
            print(f"  line {n}: {text!r}: {why}", file=sys.stderr)
        return 0

    if a.cmd == "convert":
        proxies = res.proxies
    else:

        def prog(done, total, r):
            if done % 25 == 0 or done == total:
                print(f"\rchecked {done}/{total}", end="", file=sys.stderr, flush=True)

        if a.detect:
            with ThreadPoolExecutor(a.workers) as ex:
                found = [
                    x
                    for x in ex.map(
                        lambda p: detect_scheme(p, url=a.url, timeout=a.timeout), res.proxies
                    )
                    if x
                ]
            proxies = found
            print(f"\n{len(proxies)} working", file=sys.stderr)
        else:
            results = check_many(res.proxies, a.url, a.timeout, a.workers, progress=prog)
            print(file=sys.stderr)
            proxies = [r.proxy for r in results if r.ok]
            if a.max_latency:
                proxies = [p for p in proxies if (p.latency_ms or 1e9) <= a.max_latency]
            print(f"{len(proxies)}/{len(results)} working", file=sys.stderr)
        if a.classify or a.kind:

            def cprog(done, total):
                print(f"\rclassified {done}/{total}", end="", file=sys.stderr, flush=True)

            cls = classify_many(
                proxies,
                workers=min(a.workers, 20),
                progress=cprog,
                rotation_samples=a.rotation_samples,
                api_key=a.api_key,
                check_url=a.url,
                timeout=a.timeout,
            )
            print(file=sys.stderr)
            counts: dict[str, int] = {}
            for _, c in cls:
                counts[c.kind] = counts.get(c.kind, 0) + 1
            print("  " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())), file=sys.stderr)
            if len(cls) <= 40:
                for p, c in sorted(cls, key=lambda x: x[1].kind):
                    print(
                        f"  {p.masked():<34} {c.kind:<11} {c.confidence:>4.0%}  "
                        f"{c.isp or '?'} [{c.country or '?'}]  {'; '.join(c.reasons[:2])}",
                        file=sys.stderr,
                    )
            if a.kind:
                proxies = [p for p in proxies if p.kind in a.kind]
                print(f"{len(proxies)} match {'/'.join(a.kind)}", file=sys.stderr)
        if a.geo:

            def gprog(done, total):
                print(f"\rgeolocated {done}/{total}", end="", file=sys.stderr, flush=True)

            geos = geolocate_many(
                proxies,
                workers=min(a.workers, 20),
                progress=gprog,
                api_key=a.api_key,
                check_url=a.url,
                timeout=a.timeout,
            )
            print(file=sys.stderr)
            print(f"  {sum(1 for _, g in geos if g)}/{len(geos)} located", file=sys.stderr)
            if len(geos) <= 40:
                for p, g in geos:
                    if g:
                        print(
                            f"  {p.masked():<34} {g.city or '?'}, {g.country_code or '?'}  "
                            f"{g.timezone or '?'}  {g.latitude},{g.longitude}  {g.locale}",
                            file=sys.stderr,
                        )
        proxies.sort(key=lambda p: p.latency_ms or 1e9)

    if a.to == "json":
        _write(a.out, export_json(proxies))
    elif a.to == "csv":
        _write(a.out, export_csv(proxies))
    else:
        _write(a.out, export_txt(proxies, a.to))
    return 0 if (a.cmd == "convert" or proxies) else 1

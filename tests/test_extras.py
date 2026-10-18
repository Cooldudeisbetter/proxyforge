"""Async paths, failover, credential scrubbing, downloader, rate limiter, pool bookkeeping."""

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import proxyforge as pk
from conftest import CHECK_URL


def _server(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---- async -----------------------------------------------------------------
def test_acheck_many(fake_proxy):
    pytest.importorskip("httpx")
    good, dead = fake_proxy(["9.9.9.9"]), pk.parse("127.0.0.1:1")
    seen = []
    results = asyncio.run(
        pk.acheck_many(
            [good, dead], url=CHECK_URL, timeout=3, progress=lambda d, t, r: seen.append((d, t))
        )
    )
    by_port = {r.proxy.port: r for r in results}
    assert by_port[good.port].ok and by_port[good.port].ip == "9.9.9.9"
    assert not by_port[1].ok
    assert sorted(seen) == [(1, 2), (2, 2)]


def test_arequest_fails_over(fake_proxy):
    pytest.importorskip("httpx")
    good, dead = fake_proxy(["9.9.9.9"]), pk.parse("127.0.0.1:1")
    pool = pk.ProxyPool([dead, good], max_failures=5)
    r = asyncio.run(pool.arequest("GET", CHECK_URL, retries=4, timeout=3))
    assert r.json()["ip"] == "9.9.9.9"


# ---- request failover / scrubbing -------------------------------------------
def test_sticky_key_fails_over_to_another_proxy(fake_proxy):
    good, dead = fake_proxy(["9.9.9.9"]), pk.parse("127.0.0.1:1")
    pool = pk.ProxyPool([dead, good], strategy="sticky", max_failures=10)
    key = next(k for k in (f"acct{i}" for i in range(200)) if pool.get(k) is dead)
    assert pool.request("GET", CHECK_URL, key=key, retries=6, timeout=3).json()["ip"] == "9.9.9.9"


def test_pool_exhausted_does_not_leak_credentials():
    p = pk.parse("http://alice:s3cretpass@127.0.0.1:1")
    pool = pk.ProxyPool([p], max_failures=10)
    with pytest.raises(pk.PoolExhausted) as ei:
        pool.request("GET", CHECK_URL, retries=2, timeout=1)
    assert "s3cretpass" not in str(ei.value) and "alice" not in str(ei.value)


def test_check_error_text_scrubs_credentials():
    p = pk.parse("http://alice:s3cretpass@127.0.0.1:1")
    res = pk.check_proxy(p, url=CHECK_URL, timeout=1)
    assert not res.ok and "s3cretpass" not in (res.error or "")


def test_bad_url_is_not_treated_as_proxy_failure(fake_proxy):
    p = fake_proxy(["9.9.9.9"])
    pool = pk.ProxyPool([p])
    with pytest.raises(Exception, match=r"(?i)schema|scheme|invalid"):
        pool.request("GET", "not-a-url", retries=3)
    assert p.failures == 0


def test_session_is_pinned_to_a_pool_proxy():
    p = pk.parse("u:p@1.2.3.4:80")
    s = pk.ProxyPool([p]).session()
    assert s.proxies["https"] == p.url() and s.proxy is p


# ---- ip extraction ---------------------------------------------------------
@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"ip": "1.2.3.4"}', "1.2.3.4"),
        ('{"origin": "5.6.7.8, 9.9.9.9"}', "5.6.7.8"),
        ("203.0.113.9\n", "203.0.113.9"),
        ("your ip is 2001:db8::1 ok", "2001:db8::1"),
        ("<html>feedback faded decade std::string 12:30:45</html>", None),
        ('{"ip": "not-an-ip"}', None),
        ("", None),
    ],
)
def test_extract_ip(text, expected):
    assert pk._extract_ip(text) == expected


# ---- downloader ------------------------------------------------------------
def test_load_url(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/missing":
                self.send_response(404)
                self.end_headers()
                return
            body = (
                b"1.1.1.1:80\n2.2.2.2:81\n"
                if self.path == "/list"
                else b"<tr><td>3.3.3.3</td><td>8080</td></tr>"
            )
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = _server(H)
    base = f"http://127.0.0.1:{srv.server_port}"
    assert len(pk.load_url(f"{base}/list")) == 2
    assert [str(p) for p in pk.load_url(f"{base}/html")] == ["http://3.3.3.3:8080"]
    with pytest.raises(ValueError, match="larger"):
        pk.load_url(f"{base}/list", max_bytes=5)
    with pytest.raises(OSError):
        pk.load_url(f"{base}/missing")
    with pytest.raises(ValueError, match="http"):
        pk.load_url("file:///etc/passwd")
    srv.shutdown()


def test_pool_from_text_and_file(tmp_path):
    f = tmp_path / "p.txt"
    f.write_text("1.1.1.1:80\r\n# c\r\nu:p@2.2.2.2:81\r\n")
    assert len(pk.ProxyPool.from_file(str(f))) == 2
    pool = pk.ProxyPool.from_text("socks5://1.1.1.1:1080", strategy="random", seed=1)
    assert pool.get().scheme == "socks5"
    assert len(pk.parse_many(["1.1.1.1:80", "1.1.1.1:80"])) == 1


# ---- ip-api client + rate limiter -----------------------------------------------
def test_rate_limiter_spaces_calls():
    rl = pk._RateLimiter(600)  # 0.1s apart
    t0 = time.monotonic()
    for _ in range(4):
        rl.wait()
    assert time.monotonic() - t0 >= 0.28


def test_lookup_ip_retries_on_429_and_caches(monkeypatch):
    monkeypatch.setattr(pk, "_IPAPI_LIMIT", pk._RateLimiter(60000))
    monkeypatch.setattr(pk, "_IP_CACHE", {})
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    calls = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path)
            if len(calls) == 1:
                self.send_response(429)
                self.send_header("X-Ttl", "0")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.dumps({"status": "success", "isp": "X", "as": "AS1 X"}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = _server(H)
    base = f"http://127.0.0.1:{srv.server_port}"
    assert pk.lookup_ip("8.8.8.8", base_url=base)["isp"] == "X"
    assert pk.lookup_ip("8.8.8.8", base_url=base)["isp"] == "X"  # cached
    assert len(calls) == 2
    srv.shutdown()


def test_reverse_dns_times_out_quietly(monkeypatch):
    def slow_resolver(ip):
        time.sleep(1)
        return ("late.example", [], [ip])

    monkeypatch.setattr(pk.socket, "gethostbyaddr", slow_resolver)
    t0 = time.monotonic()
    assert pk.reverse_dns("1.2.3.4", timeout=0.2) is None
    assert time.monotonic() - t0 < 2


def test_detect_scheme(fake_proxy):
    p = fake_proxy(["9.9.9.9"])
    p.scheme = "socks5"
    found = pk.detect_scheme(p, schemes=("socks5", "http"), url=CHECK_URL, timeout=3)
    assert found is not None and found.scheme == "http"
    assert (
        pk.detect_scheme(pk.parse("127.0.0.1:1"), schemes=("http",), url=CHECK_URL, timeout=1)
        is None
    )


# ---- pool bookkeeping ------------------------------------------------------
def test_ban_backoff_doubles_and_unban():
    p = pk.parse("1.1.1.1:80")
    pool = pk.ProxyPool([p], cooldown=10, max_failures=1, max_cooldown=35)
    pool.report_failure(p)
    first = p.banned_until - time.time()
    assert 9 < first <= 10 and p.banned
    pool.unban_all()
    pool.report_failure(p)
    assert 19 < p.banned_until - time.time() <= 20
    pool.unban_all()
    pool.report_failure(p)
    pool.unban_all()
    pool.report_failure(p)
    assert p.banned_until - time.time() <= 35  # capped
    pool.unban_all()
    assert pool.available() == [p]


def test_lease_reports_outcome():
    p = pk.parse("1.1.1.1:80")
    pool = pk.ProxyPool([p], max_failures=2)
    with pool.lease() as got:
        assert got is p
    assert p.successes == 1
    with pytest.raises(RuntimeError), pool.lease():
        raise RuntimeError("boom")
    assert p.failures == 1


def test_add_remove_dedupe_and_stats_mask_passwords():
    pool = pk.ProxyPool()
    assert pool.add("u:secret@1.1.1.1:80") and not pool.add("u:secret@1.1.1.1:80")
    assert "secret" not in json.dumps(pool.stats())
    assert "secret" not in pk.export_json(pool, include_password=False)
    assert "secret" in pk.export_json(pool)
    pool.remove(next(iter(pool)))
    assert len(pool) == 0
    with pytest.raises(ValueError):
        pk.ProxyPool(strategy="nope")


def test_pool_check_drops_dead(fake_proxy):
    good, dead = fake_proxy(["9.9.9.9"]), pk.parse("127.0.0.1:1")
    pool = pk.ProxyPool([good, dead])
    pool.check(url=CHECK_URL, timeout=2)
    assert list(pool) == [good]


def test_fastest_prefers_low_latency():
    fast, slow = pk.parse("1.1.1.1:80"), pk.parse("2.2.2.2:80")
    fast.latency_ms, slow.latency_ms = 10.0, 5000.0
    pool = pk.ProxyPool([fast, slow], strategy="fastest", seed=7)
    picks = [pool.get() for _ in range(200)]
    assert picks.count(fast) > 150


def test_format_rejects_unknown():
    with pytest.raises(ValueError):
        pk.parse("u:p@1.2.3.4:80").format("nope")

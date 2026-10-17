import pytest

import proxyforge as pk
from conftest import CHECK_URL


def test_check_many(fake_proxy):
    good, dead = fake_proxy(["9.9.9.9"]), pk.parse("127.0.0.1:1")
    results = pk.check_many([good, dead], url=CHECK_URL, timeout=3, workers=4)
    res = {r.proxy.port: r for r in results}
    assert res[good.port].ok and res[good.port].ip == "9.9.9.9"
    assert not res[1].ok


def test_pool_rotates_past_and_bans_dead_proxy(fake_proxy):
    good, dead = fake_proxy(["9.9.9.9"]), pk.parse("127.0.0.1:1")
    pool = pk.ProxyPool([good, dead], max_failures=2, cooldown=60)
    for _ in range(6):
        r = pool.request("GET", CHECK_URL, retries=3, timeout=3)
    assert r.json()["ip"] == "9.9.9.9"
    assert dead.banned and not good.banned
    assert pool.available() == [good]


def test_pool_raises_when_everything_is_banned():
    p = pk.parse("127.0.0.1:1")
    pool = pk.ProxyPool([p], max_failures=1)
    pool.report_failure(p)
    with pytest.raises(pk.NoProxyAvailable):
        pool.get()


def test_sticky_is_stable_and_spreads():
    pool = pk.ProxyPool([pk.parse(f"10.0.0.{i}:80") for i in range(1, 9)], strategy="sticky")
    assert len({pool.get("acct1").key for _ in range(20)}) == 1
    assert len({pool.get(f"acct{i}").key for i in range(40)}) > 1


@pytest.mark.parametrize("strategy", pk.ProxyPool.STRATEGIES)
def test_all_strategies_return_a_proxy(strategy):
    pool = pk.ProxyPool([pk.parse(f"10.0.0.{i}:80") for i in range(1, 4)], strategy=strategy)
    assert pool.get("k") in list(pool)


def test_exports_include_kind_columns(fake_proxy):
    header = pk.export_csv([pk.parse("1.2.3.4:80")]).splitlines()[0]
    assert "kind" in header and "isp" in header

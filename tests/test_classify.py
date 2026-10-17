import proxyforge as pk
from conftest import CHECK_URL


def _info(isp, asn, cc="US", **flags):
    return {
        "isp": isp,
        "org": "",
        "as": asn,
        "countryCode": cc,
        "mobile": False,
        "proxy": False,
        "hosting": False,
        **flags,
    }


def _kw(base):
    return {"check_url": CHECK_URL, "timeout": 3, "base_url": base}


def test_rotating_consumer_isps_are_residential(fake_proxy, fake_ipapi):
    base, db, rdns = fake_ipapi
    db.update(
        {
            "73.1.1.1": _info("Comcast Cable", "AS7922 Comcast", proxy=True),
            "98.2.2.2": _info("Verizon Fios", "AS701 Verizon"),
            "24.3.3.3": _info("Charter Communications", "AS20115 Charter"),
        }
    )
    rdns.update(
        {
            "73.1.1.1": "c-73-1-1-1.hsd1.fl.comcast.net",
            "98.2.2.2": "pool-98-2-2-2.nycmny.fios.verizon.net",
        }
    )
    p = fake_proxy(["73.1.1.1", "98.2.2.2", "24.3.3.3"])
    c = pk.classify(p, rotation_samples=5, **_kw(base))
    assert c.kind == "residential" and c.rotates and c.unique_ips == 3
    assert c.confidence >= 0.85
    assert (p.kind, p.country) == ("residential", "US")


def test_hosting_flag_means_datacenter(fake_proxy, fake_ipapi):
    base, db, _ = fake_ipapi
    db["3.5.5.5"] = _info("Amazon.com, Inc.", "AS16509 Amazon", hosting=True, proxy=True)
    c = pk.classify(fake_proxy(["3.5.5.5"]), rotation_samples=3, **_kw(base))
    assert c.kind == "datacenter" and c.rotates is False and c.known_proxy


def test_mobile_carrier(fake_proxy, fake_ipapi):
    base, db, _ = fake_ipapi
    db["80.1.1.1"] = _info("Digicel", "AS33576 Digicel", "JM", mobile=True)
    assert pk.classify(fake_proxy(["80.1.1.1"]), **_kw(base)).kind == "mobile"


def test_server_style_rdns_overrides_neutral_isp_name(fake_proxy, fake_ipapi):
    base, db, rdns = fake_ipapi
    db["5.9.9.9"] = _info("Totally Normal Telecom", "AS65000 Normal", "DE")
    rdns["5.9.9.9"] = "vps123.somewhere.net"
    assert pk.classify(fake_proxy(["5.9.9.9"]), **_kw(base)).kind == "datacenter"


def test_failed_lookup_and_dead_proxy_are_unknown(fake_proxy, fake_ipapi):
    base, _, _ = fake_ipapi
    assert pk.classify(fake_proxy(["1.1.1.1"]), **_kw(base)).kind == "unknown"
    dead = pk.parse("127.0.0.1:1")
    assert pk.classify(dead, check_url=CHECK_URL, timeout=1, base_url=base).kind == "unknown"


def test_pool_only_filters_by_kind(fake_proxy, fake_ipapi):
    base, db, _ = fake_ipapi
    db["73.1.1.1"] = _info("Comcast Cable", "AS7922 Comcast")
    db["3.5.5.5"] = _info("Amazon.com, Inc.", "AS16509 Amazon", hosting=True)
    a, b = fake_proxy(["73.1.1.1"]), fake_proxy(["3.5.5.5"])
    pool = pk.ProxyPool([a, b])
    pool.classify(**_kw(base))
    assert list(pool.only("residential")) == [a]
    assert list(pool.only("datacenter")) == [b]

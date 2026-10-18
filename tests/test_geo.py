import csv
import io
import json

import pytest

import proxyforge as pk
from conftest import CHECK_URL

JAMAICA = {
    "country": "Jamaica",
    "countryCode": "JM",
    "regionName": "Kingston",
    "city": "Kingston",
    "zip": "",
    "lat": 17.9712,
    "lon": -76.7936,
    "timezone": "America/Jamaica",
    "offset": -18000,
    "currency": "JMD",
    "isp": "Digicel",
    "org": "",
    "as": "AS33576 Digicel",
    "mobile": False,
    "proxy": False,
    "hosting": False,
}
MEXICO = {
    **JAMAICA,
    "country": "Mexico",
    "countryCode": "MX",
    "city": "Mexico City",
    "timezone": "America/Mexico_City",
    "lat": 19.43,
    "lon": -99.13,
    "currency": "MXN",
}


def _kw(base):
    return {"check_url": CHECK_URL, "timeout": 3, "base_url": base}


def test_geolocate_ip_fields(fake_ipapi):
    base, db, _ = fake_ipapi
    db["80.1.1.1"] = JAMAICA
    g = pk.geolocate_ip("80.1.1.1", base_url=base)
    assert (g.country_code, g.city, g.region) == ("JM", "Kingston", "Kingston")
    assert (g.latitude, g.longitude) == (17.9712, -76.7936)
    assert (g.timezone, g.utc_offset, g.currency) == ("America/Jamaica", -18000, "JMD")
    assert g.zip is None  # empty strings become None
    assert (g.locale, g.locale_fallback) == ("en-JM", False)
    assert g.accept_language == "en-JM,en;q=0.9"


def test_locale_and_accept_language(fake_ipapi):
    base, db, _ = fake_ipapi
    db["1.1.1.1"] = MEXICO
    g = pk.geolocate_ip("1.1.1.1", base_url=base)
    assert g.locale == "es-MX"
    assert g.accept_language == "es-MX,es;q=0.9,en;q=0.8"
    assert g.headers() == {"Accept-Language": g.accept_language}
    assert pk.locale_for_country("us") == ("en-US", True)
    assert pk.locale_for_country("ZZ") == ("en-US", False)
    assert pk.locale_for_country(None) == ("en-US", False)


def test_unknown_country_falls_back_and_says_so(fake_ipapi):
    base, db, _ = fake_ipapi
    db["2.2.2.2"] = {**JAMAICA, "countryCode": "ZZ"}
    g = pk.geolocate_ip("2.2.2.2", base_url=base)
    assert (g.locale, g.locale_fallback) == ("en-US", True)


def test_playwright_context_and_geolocation(fake_ipapi):
    base, db, _ = fake_ipapi
    db["1.1.1.1"] = MEXICO
    g = pk.geolocate_ip("1.1.1.1", base_url=base)
    ctx = g.playwright_context(accuracy=50)
    assert ctx["locale"] == "es-MX" and ctx["timezone_id"] == "America/Mexico_City"
    assert ctx["geolocation"] == {"latitude": 19.43, "longitude": -99.13, "accuracy": 50}
    assert ctx["permissions"] == ["geolocation"]
    assert ctx["extra_http_headers"]["Accept-Language"].startswith("es-MX")
    lean = g.playwright_context(grant_geolocation=False, include_header=False)
    assert "permissions" not in lean and "extra_http_headers" not in lean


def test_missing_coordinates(fake_ipapi):
    base, db, _ = fake_ipapi
    db["3.3.3.3"] = {k: v for k, v in JAMAICA.items() if k not in ("lat", "lon", "timezone")}
    g = pk.geolocate_ip("3.3.3.3", base_url=base)
    assert g.latitude is None and g.timezone is None
    with pytest.raises(ValueError):
        g.geolocation()
    ctx = g.playwright_context()
    assert "geolocation" not in ctx and "timezone_id" not in ctx and ctx["locale"] == "en-JM"


def test_geolocate_proxy_sets_geo_and_exports(fake_proxy, fake_ipapi):
    base, db, _ = fake_ipapi
    db["80.1.1.1"] = JAMAICA
    p = fake_proxy(["80.1.1.1"])
    g = pk.geolocate(p, **_kw(base))
    assert p.geo is g and p.exit_ip == "80.1.1.1"
    row = json.loads(pk.export_json([p]))[0]
    assert (row["city"], row["timezone"], row["locale"]) == ("Kingston", "America/Jamaica", "en-JM")
    assert row["latitude"] == 17.9712
    csv_row = next(csv.DictReader(io.StringIO(pk.export_csv([p]))))
    assert csv_row["timezone"] == "America/Jamaica" and csv_row["city"] == "Kingston"


def test_refresh_makes_a_new_request_for_rotating_proxies(fake_proxy, fake_ipapi):
    base, db, _ = fake_ipapi
    db["80.1.1.1"], db["1.1.1.1"] = JAMAICA, MEXICO
    p = fake_proxy(["80.1.1.1", "1.1.1.1"])
    assert pk.geolocate(p, **_kw(base)).country_code == "JM"
    assert pk.geolocate(p, **_kw(base)).country_code == "JM"  # cached exit IP reused
    assert pk.geolocate(p, refresh=True, **_kw(base)).country_code == "MX"


def test_geolocate_errors(fake_proxy, fake_ipapi):
    base, _, _ = fake_ipapi
    with pytest.raises(LookupError):
        pk.geolocate(pk.parse("127.0.0.1:1"), check_url=CHECK_URL, timeout=1, base_url=base)
    with pytest.raises(RuntimeError, match="reserved"):  # ip-api has nothing for this IP
        pk.geolocate(fake_proxy(["9.9.9.9"]), **_kw(base))


def test_geolocate_many_and_pool(fake_proxy, fake_ipapi):
    base, db, _ = fake_ipapi
    db["80.1.1.1"] = JAMAICA
    good, bad = fake_proxy(["80.1.1.1"]), pk.parse("127.0.0.1:1")
    seen = []
    res = pk.geolocate_many([good, bad], progress=lambda d, t: seen.append((d, t)), **_kw(base))
    by_port = {p.port: g for p, g in res}
    assert by_port[good.port].city == "Kingston" and by_port[bad.port] is None
    assert sorted(seen) == [(1, 2), (2, 2)]
    pool = pk.ProxyPool([good])
    assert pool.geolocate(**_kw(base))[0][1].timezone == "America/Jamaica"


def test_cli_geo(tmp_path, fake_proxy, fake_ipapi, monkeypatch, capsys):
    _, db, _ = fake_ipapi
    db["80.1.1.1"] = JAMAICA
    monkeypatch.setattr(pk, "lookup_ip", lambda ip, *a, **kw: db[ip])
    p = fake_proxy(["80.1.1.1"])
    f = tmp_path / "in.txt"
    f.write_text(f"{p.host}:{p.port}\n")
    code = pk.main(["check", str(f), "--url", CHECK_URL, "--timeout", "3", "--geo", "--to", "json"])
    cap = capsys.readouterr()
    assert code == 0
    row = json.loads(cap.out)[0]
    assert row["city"] == "Kingston" and row["timezone"] == "America/Jamaica"
    assert "Kingston" in cap.err and "en-JM" in cap.err


def test_lookup_requests_geo_fields(fake_ipapi, monkeypatch):
    """The ip-api `fields` parameter must ask for everything Geo needs."""
    import requests

    seen = {}
    real_get = requests.get

    def spy(url, params=None, **kw):
        seen["fields"] = (params or {})["fields"]
        return real_get(url, params=params, **kw)

    base, db, _ = fake_ipapi
    db["80.1.1.1"] = JAMAICA
    monkeypatch.setattr(requests, "get", spy)
    pk.lookup_ip("80.1.1.1", base_url=base)
    for field in ("lat", "lon", "timezone", "offset", "regionName", "countryCode"):
        assert field in seen["fields"].split(",")

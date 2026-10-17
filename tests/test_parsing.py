import pytest

import proxyforge as pk

CASES = {
    "1.2.3.4:8080": ("http", "1.2.3.4", 8080, None, None),
    "http://u:p@1.2.3.4:8080": ("http", "1.2.3.4", 8080, "u", "p"),
    "socks5://1.2.3.4:1080": ("socks5", "1.2.3.4", 1080, None, None),
    "u:p@1.2.3.4:8080": ("http", "1.2.3.4", 8080, "u", "p"),
    "1.2.3.4:8080@u:p": ("http", "1.2.3.4", 8080, "u", "p"),
    "1.2.3.4:8080@bob:1234": ("http", "1.2.3.4", 8080, "bob", "1234"),
    "1.2.3.4:8080:u:p": ("http", "1.2.3.4", 8080, "u", "p"),
    "u:p:1.2.3.4:8080": ("http", "1.2.3.4", 8080, "u", "p"),
    "user:pa@ss@proxy.example.com:3128": ("http", "proxy.example.com", 3128, "user", "pa@ss"),
    "[2001:db8::1]:8080": ("http", "2001:db8::1", 8080, None, None),
    "http://us%40er:p%3Aw@host.io:80": ("http", "host.io", 80, "us@er", "p:w"),
    "proxy.example.com:3128:me:secret": ("http", "proxy.example.com", 3128, "me", "secret"),
}


@pytest.mark.parametrize("text,expected", CASES.items())
def test_parse(text, expected):
    p = pk.parse(text)
    assert (p.scheme, p.host, p.port, p.username, p.password) == expected


BAD = ["", "abc", "1.2.3.4:99999", "ftp://1.2.3.4:80", "1.2.3.4", "a:b:c"]


@pytest.mark.parametrize("bad", BAD)
def test_parse_rejects(bad):
    with pytest.raises(pk.ProxyParseError):
        pk.parse(bad)


def test_parse_many_dedupes_and_reports_errors():
    r = pk.parse_many("# c\n1.1.1.1:80 2.2.2.2:81\n1.1.1.1:80\nbad\nu:p@3.3.3.3:82")
    assert len(r) == 3 and r.duplicates == 1 and len(r.errors) == 1


def test_extract_from_text_and_html():
    found = pk.extract("<tr><td>5.5.5.5</td><td>8080</td></tr> socks5://6.6.6.6:1080 7.7.7.7:3128")
    assert {str(p) for p in found} == {
        "http://5.5.5.5:8080",
        "socks5://6.6.6.6:1080",
        "http://7.7.7.7:3128",
    }


def test_formatting_and_masking():
    p = pk.parse("u:p@1.2.3.4:80")
    assert p.format("host:port:user:pass") == "1.2.3.4:80:u:p"
    assert p.format("user:pass:host:port") == "u:p:1.2.3.4:80"
    assert p.playwright()["username"] == "u"
    assert "p@" not in repr(p)
    assert pk.parse(p.url()) == p

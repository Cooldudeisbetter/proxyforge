import json
import os
import stat

import pytest

import proxyforge as pk
from conftest import CHECK_URL


def run(*argv):
    return pk.main([str(a) for a in argv])


def test_version(capsys):
    with pytest.raises(SystemExit) as ei:
        run("--version")
    assert ei.value.code == 0
    assert pk.__version__ in capsys.readouterr().out


def test_parse_reports_errors(tmp_path, capsys):
    f = tmp_path / "in.txt"
    f.write_text("1.2.3.4:80\ngarbage\n")
    assert run("parse", f) == 0
    err = capsys.readouterr().err
    assert "1 errors" in err and "garbage" in err


def test_convert_formats_and_file_permissions(tmp_path, capsys):
    f, out = tmp_path / "in.txt", tmp_path / "out.txt"
    f.write_text("1.2.3.4:80\nu:p@5.6.7.8:3128\n")
    assert run("convert", f, "--to", "host:port:user:pass", "-o", out) == 0
    assert out.read_text() == "1.2.3.4:80\n5.6.7.8:3128:u:p\n"
    if os.name == "posix":
        assert stat.S_IMODE(out.stat().st_mode) == 0o600  # may contain credentials
    assert run("convert", f, "--to", "json") == 0
    assert json.loads(capsys.readouterr().out)[1]["password"] == "p"


def test_convert_reads_stdin(monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("1.2.3.4:80\n"))
    assert run("convert", "-", "--to", "host:port") == 0
    assert capsys.readouterr().out == "1.2.3.4:80\n"


def test_missing_file_exit_code(tmp_path, capsys):
    assert run("parse", tmp_path / "nope.txt") == 2
    assert "could not load" in capsys.readouterr().err


def test_check_keeps_working_proxies(tmp_path, fake_proxy, capsys):
    good = fake_proxy(["9.9.9.9"])
    f = tmp_path / "in.txt"
    f.write_text(f"{good.host}:{good.port}\n127.0.0.1:1\n")
    assert run("check", f, "--url", CHECK_URL, "--timeout", 3, "--workers", 4) == 0
    assert capsys.readouterr().out.strip() == f"http://{good.host}:{good.port}"


def test_check_exit_code_1_when_nothing_works(tmp_path, capsys):
    f = tmp_path / "in.txt"
    f.write_text("127.0.0.1:1\n")
    assert run("check", f, "--url", CHECK_URL, "--timeout", 1) == 1


def test_check_max_latency_filters(tmp_path, fake_proxy, capsys):
    good = fake_proxy(["9.9.9.9"])
    f = tmp_path / "in.txt"
    f.write_text(f"{good.host}:{good.port}\n")
    assert run("check", f, "--url", CHECK_URL, "--max-latency", "0.0001") == 1


def test_check_classify_and_kind_filter(tmp_path, fake_proxy, fake_ipapi, monkeypatch, capsys):
    _, db, rdns = fake_ipapi
    db["73.1.1.1"] = {
        "isp": "Comcast Cable",
        "org": "",
        "as": "AS7922 Comcast",
        "mobile": False,
        "proxy": False,
        "hosting": False,
        "countryCode": "US",
    }
    db["3.5.5.5"] = {
        "isp": "Amazon.com, Inc.",
        "org": "",
        "as": "AS16509 Amazon",
        "mobile": False,
        "proxy": False,
        "hosting": True,
        "countryCode": "US",
    }
    rdns["73.1.1.1"] = "c-73-1-1-1.hsd1.fl.comcast.net"
    monkeypatch.setattr(pk, "lookup_ip", lambda ip, *a, **kw: db[ip])
    resi, dc = fake_proxy(["73.1.1.1"]), fake_proxy(["3.5.5.5"])
    f = tmp_path / "in.txt"
    f.write_text(f"{resi.host}:{resi.port}\n{dc.host}:{dc.port}\n")
    code = run(
        "check", f, "--url", CHECK_URL, "--timeout", 3, "--kind", "residential", "--to", "json"
    )
    cap = capsys.readouterr()
    assert code == 0
    rows = json.loads(cap.out)
    assert [r["kind"] for r in rows] == ["residential"] and rows[0]["port"] == resi.port
    assert "datacenter: 1" in cap.err and "residential: 1" in cap.err


def test_verbose_flag_enables_logging(tmp_path, capsys):
    f = tmp_path / "in.txt"
    f.write_text("1.2.3.4:80\n")
    assert run("-vv", "parse", f) == 0


def test_check_detect_scheme(tmp_path, fake_proxy, capsys):
    good = fake_proxy(["9.9.9.9"])
    f = tmp_path / "in.txt"
    f.write_text(f"socks5://{good.host}:{good.port}\n")
    assert run("check", f, "--detect", "--url", CHECK_URL, "--timeout", 3) == 0
    assert capsys.readouterr().out.strip() == f"http://{good.host}:{good.port}"


def test_python_dash_m_entrypoint():
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-m", "proxyforge", "--version"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert pk.__version__ in out

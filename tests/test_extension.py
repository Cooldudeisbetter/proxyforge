import json
import zipfile

import pytest

import proxyforge as pk
from test_cli import run


def test_zip_export_has_manifest_and_credentials(tmp_path):
    p = pk.parse("user:p@ss@1.2.3.4:8080")
    out = p.chrome_extension(tmp_path / "ext.zip")
    with zipfile.ZipFile(out) as z:
        assert sorted(z.namelist()) == ["background.js", "manifest.json"]
        manifest = json.loads(z.read("manifest.json"))
        js = z.read("background.js").decode()
    assert manifest["manifest_version"] == 3
    assert "webRequestAuthProvider" in manifest["permissions"]
    assert '"host": "1.2.3.4"' in js and '"password": "p@ss"' in js


def test_directory_export_and_permissions(tmp_path):
    out = pk.build_chrome_extension(pk.parse("1.2.3.4:80"), tmp_path / "ext", name="mine")
    assert json.loads((tmp_path / "ext" / "manifest.json").read_text())["name"] == "mine"
    assert (tmp_path / "ext" / "background.js").exists() and out == str(tmp_path / "ext")


def test_hostile_password_stays_valid_js_string(tmp_path):
    p = pk.Proxy("1.2.3.4", 80, username="u", password='"; alert(1); //')
    out = p.chrome_extension(tmp_path / "e.zip")
    js = zipfile.ZipFile(out).read("background.js").decode()
    cfg = json.loads(js.split("const PROXY = ", 1)[1].split(";\n", 1)[0])
    assert cfg["password"] == '"; alert(1); //'


def test_socks_mapping_and_auth_rejected(tmp_path):
    out = pk.parse("socks5h://1.2.3.4:1080").chrome_extension(tmp_path / "s.zip")
    assert '"scheme": "socks5"' in zipfile.ZipFile(out).read("background.js").decode()
    with pytest.raises(ValueError, match="SOCKS"):
        pk.parse("socks5://u:p@1.2.3.4:1080").chrome_extension(tmp_path / "x.zip")


def test_cli_extension(tmp_path, capsys):
    out = tmp_path / "e.zip"
    assert run("extension", "u:p@1.2.3.4:80", "-o", out) == 0
    assert zipfile.is_zipfile(out)
    assert run("extension", "not a proxy", "-o", out) == 2


def test_crx3_is_signed_and_reuses_key(tmp_path):
    pytest.importorskip("cryptography")
    import io
    import struct
    from hashlib import sha256

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    out = pk.parse("u:p@1.2.3.4:80").chrome_extension(tmp_path / "e.crx")
    data = (tmp_path / "e.crx").read_bytes()
    magic, version, hlen = struct.unpack("<4sII", data[:12])
    assert (magic, version) == (b"Cr24", 3)
    header, body = data[12 : 12 + hlen], data[12 + hlen :]
    assert zipfile.ZipFile(io.BytesIO(body)).namelist() == ["manifest.json", "background.js"]

    key = serialization.load_pem_private_key((tmp_path / "e.pem").read_bytes(), None)
    pub = key.public_key()
    der = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signed_data = pk._pb_field(1, sha256(der).digest()[:16])
    assert der in header and header.endswith(signed_data)
    sig_at = header.index(b"\x12\x80\x02") + 3  # signature field: tag, varint length 256
    sig = header[sig_at : sig_at + 256]
    pub.verify(
        sig,
        b"CRX3 SignedData\x00" + struct.pack("<I", len(signed_data)) + signed_data + body,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    assert len(pk.crx_extension_id(der)) == 32

    pem = (tmp_path / "e.pem").read_bytes()
    pk.parse("u:p@5.6.7.8:80").chrome_extension(tmp_path / "e.crx")
    assert (tmp_path / "e.pem").read_bytes() == pem and out.endswith("e.crx")

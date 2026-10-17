import itertools
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import proxyforge as pk

CHECK_URL = "http://example.test/ip"


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def fake_proxy():
    """fake_proxy(["1.1.1.1", "2.2.2.2"]) -> Proxy answering with those exit IPs in turn."""
    servers = []

    def make(ips):
        cycle = itertools.cycle(ips)

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({"ip": next(cycle)}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = _serve(H)
        servers.append(srv)
        return pk.parse(f"127.0.0.1:{srv.server_port}")

    yield make
    for s in servers:
        s.shutdown()


@pytest.fixture
def fake_ipapi(monkeypatch):
    """Local stand-in for ip-api.com. Returns (base_url, db, rdns) - mutate db/rdns per test."""
    monkeypatch.setattr(pk, "_IPAPI_LIMIT", pk._RateLimiter(60000))
    monkeypatch.setattr(pk, "_IP_CACHE", {})
    db: dict = {}
    rdns: dict = {}
    monkeypatch.setattr(pk, "reverse_dns", lambda ip, timeout=2.0: rdns.get(ip))

    class API(BaseHTTPRequestHandler):
        def do_GET(self):
            ip = self.path.split("/json/")[1].split("?")[0]
            d = db.get(ip)
            body = json.dumps(
                {"status": "success", **d} if d else {"status": "fail", "message": "reserved range"}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = _serve(API)
    yield f"http://127.0.0.1:{srv.server_port}", db, rdns
    srv.shutdown()

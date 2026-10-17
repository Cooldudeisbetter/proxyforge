# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-17

First public release.

### Added
- Proxy parser for `host:port`, `user:pass@host:port`, `host:port@user:pass`,
  `host:port:user:pass`, `user:pass:host:port`, `scheme://...` and `[ipv6]:port`,
  with duplicate detection and per-line error reporting.
- `extract()` for pulling proxies out of free text and HTML tables; `load_file()` and
  size-capped `load_url()`.
- Threaded (`check_many`) and asyncio (`acheck_many`) proxy checkers that record latency
  and exit IP; `detect_scheme()` for http/socks5/socks4 auto-detection.
- `ProxyPool` with `round_robin`, `random`, `least_used`, `fastest` and `sticky`
  strategies, exponential-backoff bans, retrying `request()` / `arequest()` with failover,
  `lease()` context manager, and `stats()` (passwords masked).
- Exit-IP classification (`classify`, `classify_many`, `ProxyPool.classify/only`) into
  residential / datacenter / mobile with a confidence score, using ip-api.com,
  reverse DNS, ISP heuristics and optional rotation sampling.
- Client adapters for requests, httpx, aiohttp, Playwright, curl and Chrome.
- Export to txt (five formats), JSON and CSV.
- `proxyforge` CLI (`parse`, `convert`, `check`) and `python -m proxyforge`;
  output files are created with owner-only permissions.

[Unreleased]: https://github.com/Cooldudeisbetter/proxyforge/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Cooldudeisbetter/proxyforge/releases/tag/v0.1.0

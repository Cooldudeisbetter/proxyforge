# Contributing

Thanks for helping out. The project is deliberately small: one module, one required dependency.

## Setup

```bash
git clone https://github.com/Cooldudeisbetter/proxyforge && cd proxyforge
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install                                      # optional: runs ruff on commit
```

## Before you open a PR

```bash
ruff check .          # lint
ruff format .         # format (CI runs `ruff format --check`)
mypy                  # type check
pytest --cov          # tests, no network needed
```

CI runs these on Linux, macOS and Windows across Python 3.9 to 3.13, so avoid syntax or stdlib
APIs newer than 3.9.

## Guidelines

- **Tests never touch the real network.** Use the `fake_proxy` and `fake_ipapi` fixtures in
  `tests/conftest.py` (local HTTP servers). A change that needs a live proxy or the real
  ip-api.com is not testable here, so keep the live-only part tiny.
- **Never log or raise with credentials.** Error text that can contain a proxy URL must go through
  `_scrub()`; use `Proxy.masked()` for display.
- New public functions need type hints, a docstring, an entry in `__all__`, and a line in
  `CHANGELOG.md` under *Unreleased*.
- Parsing changes need a new row in `tests/test_parsing.py` for the format you are adding or fixing.
- Keep the core dependency list at `requests`. Anything heavier belongs behind an extra.

## Reporting bugs

Use the bug-report template. Please redact proxy hosts and credentials from logs. For security
issues see [SECURITY.md](SECURITY.md) instead of opening a public issue.

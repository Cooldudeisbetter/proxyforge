# Security policy

## Supported versions

Only the latest released version receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Security tab -> "Report a vulnerability"** on this repository. Include the version, a minimal
reproduction, and the impact you see. You can expect an acknowledgement within a few days.

## What counts

Examples of in-scope problems: credentials appearing in logs, exceptions or exported files that
should have been masked; unsafe file permissions on generated output; unbounded downloads or
resource use in `load_url()`; parser input that causes excessive CPU (regex backtracking).

## Handling credentials safely

- `repr()` and `Proxy.masked()` never include credentials. `str(proxy)` and `proxy.url()` do,
  because they are meant to be passed to HTTP clients.
- The CLI creates output files with mode `0600` on POSIX systems, since proxy lists often
  contain passwords. Keep proxy lists out of version control (see `.gitignore`).
- `Proxy.curl_args()` puts the password on a command line, which other local users can see in the
  process list. Prefer a `--proxy-user` file/`.curlrc` for shared machines.
- IP classification sends exit IPs to ip-api.com, over plain HTTP on its free tier. Pass an API key
  (HTTPS) or skip `--classify` if that matters for your threat model.

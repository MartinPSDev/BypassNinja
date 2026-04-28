# Changelog

All notable changes to **BypassNinja** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.2] - 2026-04-28

### Fixed

- **`first_success_result` global variable bug**: Converted from a module-level global to an instance attribute (`self.first_success_result`). Previously, `print_summary()` and `save_results()` always read `None` because `run()` assigned to a local variable instead of the global. This silently broke the output when `--stop-on-success` triggered on a redirect (301/302).

- **Unicode bypasses silently multiplying requests**: The `try_request()` method internally generated Unicode URL variations and IP header variations inside nested loops, inflating the real request count by ~7x without notifying the user. Additionally, the loops were non-functional — `try_request()` always returned on the first iteration, so variations were never actually tested.

- **`generate_headers_with_ip_bypass` only worked with proxy**: IP header bypass variations (`X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `CF-Connecting-IP`) were only generated when a proxy was configured, because `ip_variations` was only populated from the proxy IP. Now variations are always generated using `127.0.0.1` as default bypass IP, the resolved target IP, and additionally the proxy IP when available.

- **Session cookies contaminating bypass results**: The `requests.Session` automatically persisted cookies set by server responses, causing subsequent bypass tests to carry stale or unwanted cookies. Added `session.cookies.clear()` before each request so every test case runs independently.

### Added

- **Modern bypass headers**: Added 18 new header templates including `X-Override-URL`, `Proxy-Host`, `X-Forwarded-Server`, `X-Forwarded-Port`, chained `X-Forwarded-For` lists, IPv6 loopback (`::1`) variants for `X-Real-IP`/`X-Client-IP`/`True-Client-IP`, `Content-Type` variations, and additional `X-HTTP-Method-Override` / `X-Method-Override` / `X-HTTP-Method` values.

- **Advanced path mutations**: Added 12 new path payloads — encoded slashes (`%2F`, `%5C`, `%252F`), null byte (`%00`), Unicode fullwidth slash (`%ef%bc%8f`), tilde/plus suffixes, backslash, Java/Tomcat bypasses (`;jsessionid=`, `..;/`, `/servlet/`), and dot-encoded traversal (`/.%2e/`).

- **Combined headers mode**: In addition to testing individual headers, the tool now generates 10 random combinations of 2-3 merged headers per URL. This simulates real-world bypass scenarios where multiple headers are needed simultaneously (e.g., `X-Forwarded-For` + `X-Original-URL` + `X-Forwarded-Proto`).

- **Enhanced WAF detection**: `detect_waf()` now uses 4 detection techniques:
  - **Signature-based** (existing): headers + body keyword matching.
  - **Status code fingerprinting**: Identifies WAF-specific codes — `444` (Nginx), `999` (LinkedIn/Custom), `520-527` (Cloudflare).
  - **Response timing anomaly**: Flags slow responses (>5s) on 403/429/503 as possible rate limiting.
  - **Response size fingerprinting**: Matches known WAF error page sizes (Cloudflare, AWS WAF, Nginx defaults).

- **Modern User-Agents**: Added 25+ new User-Agent strings for AI crawlers, LLM agents (OpenAI, Anthropic, Google AI, Meta AI, Perplexity), and AI agent frameworks (LangChain, AutoGPT, CrewAI, MCP).

- **Richer JSON output**: Added `response_time` field to all results (successful bypasses and redirects). The `stopped_on_redirect` entry now includes `waf_detected` and `captcha_detected` fields for complete post-analysis parity with successful bypasses.

- **HTTP/2 support**: New `--http2` flag enables HTTP/2 requests via `httpx`. Some WAFs treat HTTP/2 traffic differently, making this an effective bypass technique. Falls back gracefully to HTTP/1.1 if `httpx` is not installed.

### Changed

- **`try_request()` simplified**: Now performs exactly **one request** per call. No internal loops or hidden variations.

- **Unicode URL variations moved to `run()`**: Variations are now generated at the test case level, making each one a separately counted and visible test case. The user now sees the real number of requests via `total_combinations`.

- **`--max-requests` now works correctly**: Since all variations are visible test cases, the limit applies to the actual total instead of just the base combinations.

- **Comments translated to English**: All inline comments across the codebase have been translated from Spanish to English for international readability.

### Removed

- `RULES.md` — Removed from the repository.
- Orphaned global `first_success_result` declarations (module-level and `__main__` block).

---

## [1.0.0] - 2025-04-10

### Added

- Initial release of BypassNinja.
- HTTP 403 bypass via path mutations, HTTP method fuzzing, and header injection.
- WAF and CAPTCHA detection.
- IP address representation variations (octal, hex, binary, DWORD, IPv6 mapped) based on [PortSwigger's URL Validation Bypass research](https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet).
- Unicode path bypass characters (zero-width space, soft hyphen, line/paragraph separators).
- Multi-threaded execution with configurable thread count.
- Burst mode (`--burst`) for fast GET/POST-only scanning.
- `--stop-on-success` to halt on first 2xx/3xx response.
- `--max-requests` to limit total request count.
- Proxy support, custom headers, cookies, SSL verification toggle.
- JSON output for results (`--output`).
- Self-update via `--update` (git pull).

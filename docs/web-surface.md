# Standard Katana web discovery (FR-2)

The previous Python crawler has been removed. `RealScopedExecutor.crawl(url)`
dispatches the `web` adapter through `ToolEngine`, which launches standard Katana
v1.8.0 with an argv list, never a shell command. No browser or headless runtime is
used or required. `http_get(url)` uses a single seed and depth 1, and returns the
target's GET record (Katana may fetch related resources).

Install the pinned, checksum-verified binary:

```powershell
python scripts/install_katana.py
```

The engine prefers `.tools/katana/katana.exe` on Windows or
`.tools/katana/katana` on Unix, then PATH. It verifies the version before each
invocation. Downloads are not committed. Installation does not change system
security settings.

## Discovery

- Katana technology fingerprints, independent of the server implementation language.
- HTML links and form actions/methods/parameter names; JavaScript source endpoint parsing.
- HTML-linked pages and generic `/login` and `/admin` seeds. Automatic
  `-known-files all` probing is disabled: with pinned Katana v1.8.0 it prevented
  discovery of the local nonstandard-port application's linked input page
  through the scoped proxy. Unlinked robots/sitemap routes are not guaranteed.
- At most one extra batch of eight technology-specific path candidates, at both
  the supplied application base and origin root: WordPress, Drupal, Joomla,
  Django, Laravel, Spring, ASP.NET, and Keycloak. Other technologies still use
  normal crawling; language detection alone cannot determine an arbitrary URL.
- Normalized method/URL inventory, query and available body parameter names,
  deduplication by method and URL, 401/403 protected, 429 rate limited,
  404/410 missing, malformed-output and partial-result metadata.

Katana form output exposes parameter names, not complete widget types or every
standalone/custom input. No JavaScript executes, so runtime XHR/fetch requests,
JS-created forms, shadow DOM and interaction-only routes may be missed. The parser
can consume XHR metadata if supplied, but standard Katana does not capture runtime
XHR traffic. This implementation does not promise exhaustive coverage or bot/WAF
bypass. CAPTCHA/challenge pages and soft 404s can return HTTP 200 and may look like
valid endpoints.

No automatic form-fill/submission or credential testing is enabled. Inventory
findings are `web_surface`, not confirmed vulnerabilities. URLs may contain query
values, but evidence summaries omit them; request bodies, cookies, authorization
headers and form values are not copied into normalized results.

## Scope and budgets

A per-crawl loopback proxy checks each resolved destination IP against the existing
scope guard and connects to a checked address. HTTP and HTTPS CONNECT are limited
to the exact starting host/port; the crawler regex additionally restricts the
scheme and authority. External redirects/resources are blocked. HTTPS stays an
end-to-end tunnel; the proxy does not decrypt TLS. Cross-origin SSO/CDNs/APIs need
separate explicitly scoped jobs. Common logout/delete links are excluded by Katana;
arbitrary GET endpoints may still have application side effects.

`config/tools.yaml` sets depth 3, 5 requests/second, concurrency 2, one input at a
time, 1 MiB response size, 100 pages/domain, 30 seconds crawl duration per target,
and a 60-second process timeout per batch. Up to two batches can run. These are
Katana fetch limits, not a global HTTP request counter. Python retains at most
500 normalized endpoints and bounded JSONL lines per batch. Partial timeout output
is preserved. Process timeout terminates that invocation's subprocess tree.

The web agent accepts network-agent `IP:port` jobs: HTTP by default, HTTPS on
port 443; use job context `scheme` for TLS on other ports. Missing binaries, tool
errors and empty output cannot be reported as successful complete scans.

## Verification

```powershell
python -m pytest tests/core/test_katana.py core/test_tool_engine.py tests/agents -q
$env:KATANA_LIVE_TESTS='1'
python -m pytest tests/core/test_katana.py -k live -q
```

The opt-in live test uses only a local HTTP fixture and passed with standard
Katana through the complete tool-engine and scope-proxy path. The offline
parser, adapter, process dispatch and real local scope-proxy tests also pass.
An earlier headless attempt encountered a Windows security warning; no system
protections were modified.

Reference: https://github.com/projectdiscovery/katana/tree/v1.8.0

"""Standard Katana adapter. Crawling, JS source parsing and fingerprints use Katana."""
import json
from pathlib import Path
import re
import socket
import subprocess
from tempfile import TemporaryDirectory
from urllib.parse import urljoin, urlsplit, urlunsplit

from core.parsers.katana import parse
from core.tool_engine import ToolExecutionError
from core.web_scope_proxy import scoped_proxy


TECH_PATHS = {
    "wordpress": ("wp-login.php", "wp-admin/"),
    "drupal": ("user/login", "admin"),
    "joomla": ("administrator/",),
    "django": ("admin/", "accounts/login/"),
    "laravel": ("login", "admin"),
    "spring": ("login",),
    "asp.net": ("Account/Login",),
    "keycloak": ("realms/",),
}


def normalize(value):
    if any(ord(c) < 33 for c in value) or "\\" in value:
        raise ValueError("Invalid URL characters")
    p = urlsplit(value)
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise ValueError("Expected HTTP(S) URL without credentials")
    host = p.hostname.encode("idna").decode().lower()
    if ":" in host:
        host = f"[{host}]"
    port = p.port
    authority = host if port in (None, 443 if p.scheme == "https" else 80) else f"{host}:{port}"
    return urlunsplit((p.scheme, authority, p.path or "/", p.query, ""))


def run(target, options, engine, guard, mode="crawl", options_override=None):
    options = {**options, **(options_override or {})}
    limits = {"depth": (3, 10), "rate_limit": (5, 100), "concurrency": (2, 10),
              "crawl_duration": (30, 30), "request_timeout": (8, 30), "max_endpoints": (500, 10000)}
    unknown = set(options) - set(limits)
    if unknown:
        raise ValueError(f"Unknown web options: {sorted(unknown)}")
    for key, (default, maximum) in limits.items():
        value = options.setdefault(key, default)
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"{key} must be an integer from 1 to {maximum}")
    target = normalize(target)
    p = urlsplit(target)
    port = p.port or (443 if p.scheme == "https" else 80)
    # ScopeManager accepts IPs/CIDRs, so resolve before calling the guard.
    for address in socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM):
        guard(address[4][0])
    scope = "^" + re.escape(urlunsplit((p.scheme, p.netloc, "", "", ""))) + r"(?:/|$)"
    root = urlunsplit((p.scheme, p.netloc, "/", "", ""))
    base = target if p.path.endswith("/") else urljoin(target, "./")
    seeds = [target]
    if mode != "get":
        seeds += [urljoin(root, path) for path in ("login", "admin")]
    raw_parts = []
    meta = {"engine": "katana", "headless": False, "javascript_execution": False, "limited": False, "passes": 0}
    max_endpoints = int(options.get("max_endpoints", 500))
    if not 1 <= max_endpoints <= 10000:
        raise ValueError("max_endpoints must be between 1 and 10000")

    with TemporaryDirectory(prefix="cyberforge-katana-") as directory, scoped_proxy(target, guard) as (proxy, blocked):
        for batch in range(2 if mode != "get" else 1):
            seed_file = Path(directory) / f"seeds-{batch}.txt"
            output = Path(directory) / f"output-{batch}.jsonl"
            seed_file.write_text("\n".join(dict.fromkeys(seeds)), encoding="utf-8")
            try:
                engine.run("katana", target=target, seeds=str(seed_file), output=str(output), proxy=proxy, scope=scope,
                           depth="1" if mode == "get" else str(options["depth"]),
                           rate_limit=str(options["rate_limit"]), concurrency=str(options["concurrency"]),
                           crawl_duration=f"{options['crawl_duration']}s", request_timeout=str(options["request_timeout"]))
            except subprocess.TimeoutExpired:
                meta.update(limited=True, error="katana_timeout")
            except ToolExecutionError:
                meta.update(limited=True, error="katana_failed")
            meta["passes"] += 1
            if output.is_file():
                # Bound output retained by Python; the process has a separate timeout.
                with output.open(encoding="utf-8", errors="replace") as stream:
                    for index, line in enumerate(stream):
                        if index >= max_endpoints or len(line) > 2 * 1024 * 1024:
                            meta["limited"] = True
                            break
                        raw_parts.append(line)
            if not raw_parts or meta.get("error"):
                if not raw_parts and not meta.get("error"):
                    meta.update(limited=True, error="katana_no_results")
                break
            pages = parse("".join(raw_parts))
            known = {row["url"] for row in pages}
            technologies = {tech.lower().split(":")[0] for row in pages for tech in row["technologies"]}
            seeds = []
            for tech, paths in TECH_PATHS.items():
                if any(tech in detected for detected in technologies):
                    for path in paths:
                        for prefix in dict.fromkeys((base, root)):
                            candidate = urljoin(prefix, path)
                            if candidate not in known:
                                seeds.append(candidate)
            seeds = list(dict.fromkeys(seeds))[:8]
            if not seeds:
                break
        meta["blocked_resources"] = bool(blocked)
        if "ScopeViolation" in blocked:
            meta.update(limited=True, error="scope_blocked")
    return json.dumps({"events": "".join(raw_parts), "meta": meta, "target": target, "max_endpoints": max_endpoints, "mode": mode})

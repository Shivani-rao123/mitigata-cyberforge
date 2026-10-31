"""
fixtures/file_manager_demo/app.py

Mirrors the real-world scenario behind this fixture's test suite
(tests/agents/test_web_agent_file_secrets.py): hitting the site's root
302-redirects to a TinyFileManager-style dynamic directory listing, which
links to a plain-text internal note containing a real secret, a
third-party CDN script, and a binary download exposed only via a
query-string-based "download" link — the kind of structure a bare-IP
pentest target can actually have, and that each broke a different part
of the web agent (now all fixed):
  - a JS-only secret scan would completely miss the .txt note (nothing
    here is JavaScript) -> native JS-bundle scan was extended to scan
    plain-text files too (_check_file_secrets).
  - the query-string download link (index.php?p=<file>&dl) has no
    extension anywhere in its URL PATH -> both _check_file_secrets() and
    _extract_binary_links() used to silently miss links shaped this way
    (fixed: both now match against the full, decoded URL).
  - the real, legitimate jQuery CDN script used to crash the entire web
    stage with an unhandled ScopeViolation the moment it was fetched
    (fixed: third-party scripts are now filtered out before fetching).

Used to live-verify (not just unit-test) that RealScopedExecutor.crawl()
follows the redirect and that agents/web/agent.py's checks all fire on
real HTTP responses, not just canned MockScopedExecutor fixtures.
"""

from flask import Flask, redirect

app = Flask(__name__)

# Same fake AWS key shape already used in fixtures/vulnerable_binary/vuln.c
# (AKIA + 16 chars = 20 total, matching gitleaks'/SECRET_PATTERNS' exact
# aws_access_key_id rule) — obviously fake, not built via concatenation
# since this exact literal already passed GitHub push-protection once.
_FAKE_AWS_KEY = "AKIAFAKEEXAMPLE12345"


@app.route("/")
def root():
    # The "bare IP redirects to the real app" case.
    return redirect("/filemanager/")


@app.route("/filemanager/")
def listing():
    return """
    <html><body>
      <h1>File Manager</h1>
      <script src="https://code.jquery.com/jquery-3.6.1.min.js"></script>
      <table>
        <tr><td><a href="/filemanager/README.txt">README.txt</a></td></tr>
        <tr><td><a href="/filemanager/ops/netops-handover.txt">netops-handover.txt</a></td></tr>
        <tr><td><a href="/index.php?p=tools%2Fagent.exe&dl">agent.exe (query-string link)</a></td></tr>
      </table>
    </body></html>
    """


@app.route("/filemanager/README.txt")
def readme():
    return "Just a readme, nothing sensitive here.", 200, {"Content-Type": "text/plain"}


@app.route("/filemanager/ops/netops-handover.txt")
def handover():
    body = f"""NetOps handover notes
----------------------
- internal AWS key for the backup bucket: {_FAKE_AWS_KEY}
- rotate this after onboarding is done.
"""
    return body, 200, {"Content-Type": "text/plain"}


# --- A second, even more common real-world shape: a TinyFileManager-style
# "download" link that passes the filename entirely as a query-string
# VALUE (index.php?p=<urlencoded path>&dl), with no file extension
# anywhere in the URL's path component at all. A path-only extension
# check misses this completely — this fixture is what surfaced that gap
# in agents/web/agent.py's _check_file_secrets() (fixed by matching
# against the full, decoded URL via _SCANNABLE_FILE_EXT_RE instead of
# just urlparse(url).path). -------------------------------------------


@app.route("/share-link")
def share_link():
    return redirect("/index.php?p=ops%2Fnetops-handover.txt&dl")


@app.route("/index.php")
def index_php():
    from flask import request

    p = request.args.get("p", "")
    if "netops-handover" in p:
        body = f"""NetOps handover notes
----------------------
- internal AWS key for the backup bucket: {_FAKE_AWS_KEY}
"""
        return body, 200, {"Content-Type": "text/plain"}
    if "agent.exe" in p:
        # A query-string-only binary download link — same shape as the
        # text-file one above, except this one has to make it all the
        # way to a binary follow-up job (agents/web/agent.py's
        # _extract_binary_links(), fixed alongside _check_file_secrets()
        # since both had the exact same path-only-extension gap).
        return b"MZ\x90\x00fake pe header", 200, {"Content-Type": "application/octet-stream"}
    return "not found", 404


if __name__ == "__main__":
    app.run(port=5099)

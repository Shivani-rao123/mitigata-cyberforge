"""
fixtures/file_manager_demo/app.py

Mirrors the real-world scenario behind this fixture's test suite
(tests/agents/test_web_agent_file_secrets.py): hitting the site's root
302-redirects to a TinyFileManager-style dynamic directory listing, which
links to a plain-text internal note containing a real secret — the kind
of structure a bare-IP pentest target can actually have, and that a
JS-only secret scan would completely miss (nothing here is JavaScript).

Used to live-verify (not just unit-test) that RealScopedExecutor.crawl()
follows the redirect and that agents/web/agent.py's
_check_file_secrets()/_check_redirect_followed() fire on real HTTP
responses, not just canned MockScopedExecutor fixtures.
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
      <table>
        <tr><td><a href="/filemanager/README.txt">README.txt</a></td></tr>
        <tr><td><a href="/filemanager/ops/netops-handover.txt">netops-handover.txt</a></td></tr>
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


if __name__ == "__main__":
    app.run(port=5099)

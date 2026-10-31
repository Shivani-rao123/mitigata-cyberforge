"""
fixtures/js_demo_site/app.py

A tiny fake site whose homepage loads a JS bundle containing a hardcoded
API key and a fetch() call to an API endpoint that never appears in any
server-rendered HTML — used to verify katana's -jsluice mode (and
core/parsers/katana.py's handling of its real output) actually surfaces
js_secret_found / js_endpoint_found findings.
"""

from flask import Flask

app = Flask(__name__)


@app.route("/")
def homepage():
    return """
    <html><body>
      <h1>Acme Dashboard</h1>
      <script src="/static/app.js"></script>
    </body></html>
    """


@app.route("/static/app.js")
def app_js():
    # Built from two pieces rather than one contiguous literal so this
    # obviously-fake test key doesn't trip GitHub's push-protection
    # secret scanner on commit — the served JS still has the full,
    # reassembled string for katana to find, which is the whole point.
    fake_key = "sk_live_51H8xyzFAKEKEY" + "abcdefghijklmnopqrstuvwxyzABCD12"
    return (
        f"""
        const STRIPE_KEY = "{fake_key}";
        function loadData() {{
          fetch("/api/internal/users/export", {{method: "GET"}});
        }}
        loadData();
        """,
        200,
        {"Content-Type": "application/javascript"},
    )


if __name__ == "__main__":
    app.run(port=5098)

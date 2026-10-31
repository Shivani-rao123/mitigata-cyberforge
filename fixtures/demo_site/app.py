"""
fixtures/demo_site/app.py

A tiny fake "company website" used ONLY to test the realistic end-to-end
scenario: a user gives CART a website, and it has to DISCOVER a
downloadable binary on its own (a "Download our tool" link) rather than
being told the file path directly. Serves the compiled vulnerable binary
from fixtures/vulnerable_binary/vuln (build it first with gcc).
"""

from flask import Flask, send_file

app = Flask(__name__)


@app.route("/")
def homepage():
    return """
    <html><body>
      <h1>Acme Corp</h1>
      <p>Welcome to our site.</p>
      <a href="/about">About</a>
      <h2>Downloads</h2>
      <a href="/downloads/acme-tool.bin">Download Acme Tool (Linux)</a>
    </body></html>
    """


@app.route("/about")
def about():
    return "<html><body><h1>About Acme Corp</h1><p>We make tools.</p></body></html>"


@app.route("/downloads/acme-tool.bin")
def download_tool():
    return send_file("../vulnerable_binary/vuln", as_attachment=True)


if __name__ == "__main__":
    app.run(port=5099)

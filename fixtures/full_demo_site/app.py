"""
fixtures/full_demo_site/app.py

One combined demo target exercising FR-1 (network), FR-2 (web), and FR-3
(binary) together, end to end — a single fake "company site" with every
planted weakness in one place, instead of separate fixtures per agent.

Weaknesses planted (deliberately, for testing only):
  - /admin — a login form (password field) -> web agent's
    default_creds_found + sensitive_endpoint_found
  - /search — reflects a GET param unescaped -> web agent's
    reflected_input
  - no security headers set -> web agent's missing_security_header
  - a "Download our tool" link -> web agent's binary-link detection,
    which hands off a follow-up job to the binary agent -> which finds
    the hardcoded secret + unsafe function in the downloaded binary

Build the binary first:  gcc -o ../vulnerable_binary/vuln ../vulnerable_binary/vuln.c
Run this:                python3 app.py        (serves on port 5100)
"""

from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/")
def homepage():
    return """
    <html><body>
      <h1>Acme Corp</h1>
      <p>Welcome to our site.</p>
      <a href="/admin">Admin</a> |
      <a href="/search">Search</a> |
      <a href="/downloads/acme-tool.bin">Download Acme Tool (Linux)</a>
    </body></html>
    """


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == "admin" and password == "admin":
            return "Welcome, admin!", 200
        return "Invalid credentials", 401
    return """
    <html><body>
      <h1>Admin Login</h1>
      <form method="post">
        <input name="username" placeholder="username">
        <input name="password" type="password" placeholder="password">
        <button type="submit">Login</button>
      </form>
    </body></html>
    """


@app.route("/search")
def search():
    query = request.args.get("q", "")
    return f"""
    <html><body>
      <h1>Search</h1>
      <form method="get" action="/search">
        <input name="q" placeholder="search...">
        <button type="submit">Go</button>
      </form>
      <p>Results for: {query}</p>
    </body></html>
    """


@app.route("/downloads/acme-tool.bin")
def download_tool():
    return send_file("../vulnerable_binary/vuln", as_attachment=True)


if __name__ == "__main__":
    app.run(port=5100)

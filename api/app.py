"""
api/app.py

FR-7 (REST API half): a small, standalone Flask app that just wires a
core/db.py Database into api/routes.py's blueprint and registers it.

Deliberately kept as its OWN app, separate from webui/app.py (the scan
dashboard) — this is a read-only API over whatever's already been
persisted, not another place a scan gets kicked off from, and keeping
it separate means nothing about the working dashboard route has to
change for this to exist.

Run directly for local/demo use:

    python -m api.app

or import create_app() to build one against a specific Database
(an in-memory one in tests, the real store/cart.db in normal use).
"""

from __future__ import annotations

from flask import Flask

from api.routes import bp
from core.db import Database


def create_app(db: Database | None = None) -> Flask:
    app = Flask(__name__)
    app.config["CART_DB"] = db if db is not None else Database()
    app.register_blueprint(bp)
    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5001)

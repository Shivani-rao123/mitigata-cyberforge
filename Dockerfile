# Dockerfile
#
# One-command setup for CART (FR-1..FR-7 engine + webui dashboard + API).
# Deliberately built from well-established, version-pinned apt packages
# only, for nmap/strings+nm/gitleaks — no "go install" / GitHub-release
# downloads in here, on purpose: those depend on a release tag/filename
# staying exactly as expected, which is a build-time failure mode you
# don't want to discover the day of a demo. apt's Debian-packaged
# binaries are about as reliable as a build dependency gets.
#
# katana (the optional JS-aware crawler) and gitleaks (the preferred,
# but not required, secret scanner) are both deliberately NOT installed
# in this image — neither has a reliable apt package across Debian
# releases (gitleaks is packaged only in Debian trixie/sid, not the
# bookworm base python:3.12-slim actually uses; katana has no Debian
# package at all, only a Go build/GitHub release). Both of this
# project's agents already handle the tool being unavailable
# gracefully and on purpose, not as an error:
#   - agents/web/agent.py's "auto" crawler mode falls back to the
#     native requests-based crawler and records a crawler_fallback
#     note when katana isn't usable.
#   - agents/binary/agent.py's secret check falls back to a built-in
#     regex scan (a real but narrower net than gitleaks) when gitleaks
#     isn't installed/configured.
# This keeps the image build 100% dependent on nmap/binutils — two of
# the most universally-available Debian packages there are — rather
# than on a release tag or a secondary distro's package staying
# available. See README.md for how to add either tool to this image
# yourself if you want the fuller coverage they give.

FROM python:3.12-slim

LABEL org.opencontainers.image.title="CART" \
      org.opencontainers.image.description="Autonomous Multi-Agent Penetration Testing Engine"

# nmap     - FR-1 network discovery
# binutils - provides `strings` and `nm`, used by FR-3's binary agent
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         nmap \
         binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps first (own layer) so an app-code-only change doesn't
# force a full pip reinstall on every rebuild.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# webui/app.py (5500) and api/app.py (5001) — see docker-compose.yml
# for which one actually runs by default and how to run the other /
# a one-off CLI command (main.py, run_pipeline.py) against this same
# image.
EXPOSE 5500 5001

CMD ["python", "webui/app.py"]

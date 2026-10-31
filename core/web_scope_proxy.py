"""Per-crawl loopback egress proxy: exact authority, checked/pinned destination IPs.

CONNECT tunnels retain end-to-end TLS. This is a network guard, not a crawler.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import select
import socket
from threading import Thread, Lock
from urllib.parse import urlsplit


@contextmanager
def scoped_proxy(target, guard):
    parsed = urlsplit(target)
    authority = (parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    blocked = set()
    lock = Lock()

    class Handler(BaseHTTPRequestHandler):
        timeout = 10
        rbufsize = 0

        def log_message(self, *args):
            pass

        def destination(self, host, port):
            if (host.lower(), port) != authority:
                raise ValueError("external destination")
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            if not addresses:
                raise OSError("DNS returned no addresses")
            for item in addresses:
                guard(item[4][0])
            # Connect the checked sockaddr directly, avoiding DNS rebinding.
            item = addresses[0]
            sock = socket.socket(item[0], item[1], item[2])
            try:
                sock.settimeout(8)
                sock.connect(item[4])
                guard(sock.getpeername()[0])
                return sock
            except Exception:
                sock.close()
                raise

        def do_CONNECT(self):
            destination = urlsplit("//" + self.path)
            self.forward(destination, tunnel=True)

        def do_GET(self):
            self.forward(urlsplit(self.path), tunnel=False)

        do_POST = do_GET
        do_PUT = do_GET
        do_PATCH = do_GET
        do_DELETE = do_GET
        do_HEAD = do_GET
        do_OPTIONS = do_GET

        def forward(self, destination, tunnel):
            upstream = None
            try:
                port = destination.port or (443 if tunnel else 80)
                if not tunnel and (destination.scheme != "http" or parsed.scheme != "http"):
                    raise ValueError("invalid proxy request")
                if destination.username or destination.password:
                    raise ValueError("embedded credentials")
                upstream = self.destination(destination.hostname or "", port)
                if tunnel:
                    self.send_response(200, "Connection established")
                    self.end_headers()
                else:
                    # Preserve the original origin-form path and Host; never forward proxy auth.
                    path = destination.path or "/"
                    if destination.query:
                        path += "?" + destination.query
                    headers = [(k, v) for k, v in self.headers.items() if k.lower() not in {"host", "proxy-authorization", "proxy-connection", "connection"}]
                    headers += [("Host", destination.netloc), ("Connection", "close")]
                    request = f"{self.command} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n"
                    upstream.sendall(request.encode("latin-1"))
                self.close_connection = True
                sockets = (self.connection, upstream)
                while True:
                    readable, _, _ = select.select(sockets, [], [], 10)
                    if not readable:
                        break
                    for source in readable:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is self.connection else self.connection).sendall(data)
            except Exception as exc:
                with lock:
                    blocked.add(type(exc).__name__)
                if upstream is None:
                    self.send_error(403, "Destination blocked or unavailable")
            finally:
                if upstream:
                    upstream.close()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", blocked
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

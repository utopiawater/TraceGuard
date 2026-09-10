import argparse
import http.client
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


class StaticProxyHandler(BaseHTTPRequestHandler):
    dist_root: Path
    api_host: str
    api_port: int

    def do_GET(self) -> None:
        if self.path.startswith("/api"):
            self._proxy()
            return
        self._serve_static()

    def do_POST(self) -> None:
        if self.path.startswith("/api"):
            self._proxy()
            return
        self.send_error(404)

    def do_OPTIONS(self) -> None:
        if self.path.startswith("/api"):
            self._proxy()
            return
        self.send_response(204)
        self.end_headers()

    def _proxy(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(length) if length else None
        headers = {key: value for key, value in self.headers.items() if key.lower() not in {"host", "connection"}}
        connection = http.client.HTTPConnection(self.api_host, self.api_port, timeout=60)
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {"connection", "transfer-encoding"}:
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)
        finally:
            connection.close()

    def _serve_static(self) -> None:
        parsed = urlparse(self.path)
        requested = parsed.path.lstrip("/") or "index.html"
        target = (self.dist_root / requested).resolve()
        if not str(target).startswith(str(self.dist_root.resolve())) or not target.is_file():
            target = self.dist_root / "index.html"
        if not target.is_file():
            self.send_error(404, "frontend build not found")
            return
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, _format: str, *args) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5173)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--root", default="frontend/dist")
    args = parser.parse_args()
    api = urlparse(args.api)
    StaticProxyHandler.dist_root = Path(args.root).resolve()
    StaticProxyHandler.api_host = api.hostname or "127.0.0.1"
    StaticProxyHandler.api_port = api.port or 8000
    server = ThreadingHTTPServer((args.host, args.port), StaticProxyHandler)
    print(f"TraceGuard static frontend serving http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()

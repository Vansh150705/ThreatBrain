"""Tiny demo web target for lab use.

Serves a plain page and writes every request to an nginx-style access log, so
the collector can detect web attacks (SQLi/XSS/traversal/scanner tools) against
it. It is NOT vulnerable — it only records requests. For demo/testing only.

    python web_target.py --port 8080 --log access.log

Then point the collector at that access.log (add it to log_paths) and attack it,
e.g.:  curl "http://<target>:8080/?id=1' OR 1=1--"   or   sqlmap -u http://<target>:8080/?id=1
"""
from __future__ import annotations

import argparse
import datetime
import http.server
import socketserver


class Handler(http.server.BaseHTTPRequestHandler):
    logfile = "access.log"

    def _log_request_line(self) -> None:
        ts = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        ua = self.headers.get("User-Agent", "-")
        line = (
            f'{self.client_address[0]} - - [{ts}] '
            f'"{self.command} {self.path} {self.request_version}" 200 32 "-" "{ua}"\n'
        )
        with open(self.logfile, "a", encoding="utf-8") as fh:
            fh.write(line)

    def do_GET(self) -> None:
        self._log_request_line()
        body = b"<h1>ThreatBrain demo target</h1><p>All requests are logged.</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *args) -> None:  # silence default stderr logging
        pass


def main() -> None:
    ap = argparse.ArgumentParser(prog="web_target")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--log", default="access.log")
    args = ap.parse_args()
    Handler.logfile = args.log
    with socketserver.TCPServer(("0.0.0.0", args.port), Handler) as httpd:
        print(f"[demo-target] listening on :{args.port}, logging to {args.log}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()

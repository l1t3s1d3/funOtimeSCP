#!/usr/bin/env python3
"""
HTTP callback listener for catching exfiltration attempts.

Run this on infrastructure you control OUTSIDE the test VPC.
Logs all incoming requests with timestamps for correlation
against the evidence timeline.

Usage:
    python network/callback-infra/listener.py 8888
    python network/callback-infra/listener.py --port 8888 --log callbacks.jsonl
"""
import datetime
import json
import sys
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

import click

LOG_FILE = "callbacks.jsonl"


class CallbackHandler(BaseHTTPRequestHandler):
    def _log_request(self, method):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "method": method,
            "path": self.path,
            "headers": dict(self.headers),
            "client_ip": self.client_address[0],
            "client_port": self.client_address[1],
            "body_length": content_length,
            "body_preview": body[:500].decode("utf-8", errors="replace")
            if body else "",
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        print(f"[{entry['timestamp']}] {method} {self.path} "
              f"from {self.client_address[0]}")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        self._log_request("GET")

    def do_POST(self):
        self._log_request("POST")

    def do_PUT(self):
        self._log_request("PUT")

    def do_DELETE(self):
        self._log_request("DELETE")

    def do_OPTIONS(self):
        self._log_request("OPTIONS")

    def log_message(self, format, *args):
        pass


@click.command()
@click.option("--port", "-p", default=8888, help="Port to listen on")
@click.option("--log", "-l", "logfile", default="callbacks.jsonl",
              help="Log file path")
@click.option("--bind", "-b", default="0.0.0.0", help="Bind address")
def main(port, logfile, bind):
    """Start the callback listener."""
    global LOG_FILE
    LOG_FILE = logfile

    print(f"Callback listener starting on {bind}:{port}")
    print(f"Logging to: {logfile}")
    print("Press Ctrl+C to stop.\n")

    server = HTTPServer((bind, port), CallbackHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()

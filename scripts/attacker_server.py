#!/usr/bin/env python3
"""Minimal static server that adds permissive CORS, so the victim's service
worker can fetch-and-cache the cross-origin payload (as a real CORS-enabled
attacker resource would). Usage: attacker_server.py <port> <directory>."""
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from functools import partial


class CORSHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8001
    directory = sys.argv[2] if len(sys.argv) > 2 else "."
    handler = partial(CORSHandler, directory=directory)
    HTTPServer(("127.0.0.1", port), handler).serve_forever()

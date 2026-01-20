#!/usr/bin/env python3
"""
Mock Mattermost Webhook Server

Receives webhook POSTs and logs them with timestamps.
Useful for testing valerter notification delivery.

Usage:
    python3 scripts/mock-mattermost.py [--port 8065]
"""

import argparse
import json
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# Stats tracking
stats = {
    "received": 0,
    "start_time": None,
}
stats_lock = threading.Lock()


class MattermostHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging
        pass

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        with stats_lock:
            stats["received"] += 1
            count = stats["received"]
            if stats["start_time"] is None:
                stats["start_time"] = datetime.now()

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        try:
            payload = json.loads(body.decode("utf-8"))
            text = payload.get("text", "<no text>")
            channel = payload.get("channel", "<default>")
            # Truncate long messages
            if len(text) > 100:
                text = text[:100] + "..."
            print(f"[{timestamp}] #{count:05d} | channel={channel} | {text}")
        except json.JSONDecodeError:
            print(f"[{timestamp}] #{count:05d} | Invalid JSON: {body[:100]}")

        # Respond with success
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def do_GET(self):
        # Health check endpoint
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()


def main():
    parser = argparse.ArgumentParser(description="Mock Mattermost Webhook Server")
    parser.add_argument("--port", type=int, default=8065, help="Port to listen on")
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), MattermostHandler)

    print("═" * 60)
    print(" Mock Mattermost Webhook Server")
    print("═" * 60)
    print()
    print(f" Listening on: http://0.0.0.0:{args.port}")
    print(f" Webhook URL:  http://localhost:{args.port}/hooks/test")
    print()
    print(" Press Ctrl+C to stop")
    print()
    print("─" * 60)
    print(" Incoming webhooks:")
    print("─" * 60)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print("─" * 60)
        print(" Summary")
        print("─" * 60)
        with stats_lock:
            print(f" Total received: {stats['received']}")
            if stats["start_time"] and stats["received"] > 0:
                elapsed = (datetime.now() - stats["start_time"]).total_seconds()
                rate = stats["received"] / elapsed if elapsed > 0 else 0
                print(f" Duration:       {elapsed:.1f}s")
                print(f" Rate:           {rate:.1f} msg/sec")
        print()


if __name__ == "__main__":
    main()

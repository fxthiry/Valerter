#!/usr/bin/env python3
"""Simple mock HTTP server to capture webhook and Mattermost notifications."""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime

class MockHandler(BaseHTTPRequestHandler):
    received_requests = []

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        request_info = {
            'timestamp': datetime.now().isoformat(),
            'path': self.path,
            'headers': dict(self.headers),
            'body': body
        }
        MockHandler.received_requests.append(request_info)

        print(f"\n{'='*60}")
        print(f"[{request_info['timestamp']}] POST {self.path}")
        print(f"Headers: {json.dumps(dict(self.headers), indent=2)}")
        print(f"Body: {body[:500]}...")
        print(f"{'='*60}")

        # Return 200 OK
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == '__main__':
    port = 18080
    server = HTTPServer(('localhost', port), MockHandler)
    print(f"Mock webhook server listening on http://localhost:{port}")
    print("Endpoints: /mattermost-hook, /webhook")
    print("Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")

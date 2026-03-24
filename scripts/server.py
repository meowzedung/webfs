import http.server
import socketserver
import sys
import argparse

# Configuration
DEFAULT_PORT = 5000
APP_NAME = "/webfs"

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        normalized_path = self.path.rstrip('/')
        if not self.path.startswith(APP_NAME):
            self.send_error(403, "Access Denied: App Name Prefix Required")
            return

        if normalized_path == APP_NAME:
            self.path = '/index.html'
        else:
            self.path = self.path[len(APP_NAME):]
            if not self.path:
                self.path = '/'

        return super().do_GET()

def serve():
    parser = argparse.ArgumentParser(description="A simple prefixed HTTP server.")
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port to listen on (default: {DEFAULT_PORT})"
    )

    args = parser.parse_args()
    port = args.port

    socketserver.TCPServer.allow_reuse_address = True

    try:
        with socketserver.TCPServer(("127.0.0.1", port), CustomHandler) as httpd:
            print(f"Serving at http://127.0.0.1:{port}{APP_NAME}/")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped.")
        sys.exit(0)
    except OSError as e:
        print(f"[ERROR] Could not start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    serve()
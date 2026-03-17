from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"HTTP/1.1 Server is Running!")

    def log_message(self, format, *args):
        pass  # suppress request logs to keep terminal clean

if __name__ == "__main__":
    ip = "127.0.0.1"
    port = 8080
    server = HTTPServer((ip, port), Handler)
    print(f"Targeting IP: {ip} on Port: {port}")
    print(f"HTTP/1.1 server running...")
    server.serve_forever()
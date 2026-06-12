from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class VulnHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        search_query = query_components.get("q", [""])[0]

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        # Deliberately vulnerable HTML (reflects search_query unsanitized)
        html = f"""
        <html>
        <body>
            <h1>Vanguard Test Target</h1>
            <form action="/" method="GET">
                <input type="text" name="q" value="test">
                <input type="submit" value="Search">
            </form>
            <p>You searched for: {search_query}</p>
        </body>
        </html>
        """
        self.wfile.write(html.encode("utf-8"))

    # To hide HTTP server logs from our terminal output for cleaner testing
    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    print("[*] Starting vulnerable test server on http://127.0.0.1:8080")
    server = HTTPServer(("127.0.0.1", 8080), VulnHandler)
    server.serve_forever()

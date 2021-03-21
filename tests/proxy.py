import socketserver
import http.server
import urllib.request
import ssl

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE


class Proxy(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        req = urllib.request.Request(
            url="https://127.0.0.1:14000" + self.path, headers=self.headers
        )
        res = urllib.request.urlopen(req, context=context)
        body = res.read()
        body = body.replace(b"https://127.0.0.1:14004", b"http://127.0.0.1:14004")
        self.send_response(res.status, res.reason)
        for header, value in res.getheaders():
            if header.lower() == "content-length":
                value = str(len(body))
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        req = urllib.request.Request(
            url="https://127.0.0.1:14000" + self.path,
            data=self.rfile,
            headers=self.headers,
        )
        res = urllib.request.urlopen(req, context=context)
        body = res.read()
        body = body.replace(b"https://127.0.0.1:14004", b"http://127.0.0.1:14004")
        self.send_response(res.status, res.reason)
        for header, value in res.getheaders():
            if header.lower() == "content-length":
                value = str(len(body))
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(body)


socketserver.ThreadingTCPServer.allow_reuse_address = True

httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 14004), Proxy)
httpd.serve_forever()

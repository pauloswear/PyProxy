import socket
import threading
import select
import time
import re
import logging
import base64

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(process)s] [%(levelname)s] %(message)s")
logg = logging.getLogger(__name__)

BACKLOG = 50
MAX_THREADS = 300
BLACKLISTED = []
MAX_CHUNK_SIZE = 16 * 1024

# Rate limiting settings for login attempts
LOGIN_RATE_LIMIT = 5  # Number of login attempts allowed per period
LOGIN_RATE_PERIOD = 60*10  # Time period
login_attempts = {}

class StaticResponse:
    connection_established = b"HTTP/1.1 200 Connection Established\r\n\r\n"
    block_response = b'HTTP/1.1 200 OK\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\nDate: Sat, 15 Feb 2020 07:04:42 GMT\r\nConnection: close\r\n\r\n<html><head><title>ISP ERROR</title></head><body><p style="text-align: center;">&nbsp;</p><p style="text-align: center;">&nbsp;</p><p style="text-align: center;">&nbsp;</p><p style="text-align: center;">&nbsp;</p><p style="text-align: center;">&nbsp;</p><p style="text-align: center;">&nbsp;</p><p style="text-align: center;"><span><strong>**YOU ARE NOT AUTHORIZED TO ACCESS THIS WEB PAGE | YOUR PROXY SERVER HAS BLOCKED THIS DOMAIN**</strong></span></p><p style="text-align: center;"><span><strong>**CONTACT YOUR PROXY ADMINISTRATOR**</strong></span></p></body></html>'

class Error:
    STATUS_503 = "Service Unavailable"
    STATUS_505 = "HTTP Version Not Supported"
    STATUS_429 = "Too Many Requests"

for key in filter(lambda x: x.startswith("STATUS"), dir(Error)):
    _, code = key.split("_")
    value = getattr(Error, f"STATUS_{code}")
    setattr(Error, f"STATUS_{code}", f"HTTP/1.1 {code} {value}\r\n\r\n".encode())

class Method:
    get = "GET"
    put = "PUT"
    head = "HEAD"
    post = "POST"
    patch = "PATCH"
    delete = "DELETE"
    options = "OPTIONS"
    connect = "CONNECT"

class Protocol:
    http10 = "HTTP/1.0"
    http11 = "HTTP/1.1"
    http20 = "HTTP/2.0"

class Request:
    def __init__(self, raw:bytes):
        self.raw = raw
        self.raw_split = raw.split(b"\r\n")
        self.log = self.raw_split[0].decode()

        self.method, self.path, self.protocol = self.log.split(" ")

        raw_host = re.findall(rb"host: (.*?)\r\n", raw.lower())

        # http protocol 1.1
        if raw_host:
            raw_host = raw_host[0].decode()
            if raw_host.find(":") != -1:
                self.host, self.port = raw_host.split(":")
                self.port = int(self.port)
            else:
                self.host = raw_host

        # http protocol 1.0 and below
        if "://" in self.path:
            path_list = self.path.split("/")
            if path_list[0] == "http:":
                self.port = 80
            if path_list[0] == "https:":
                self.port = 443

            host_n_port = path_list[2].split(":")
            if len(host_n_port) == 1:
                self.host = host_n_port[0]

            if len(host_n_port) == 2:
                self.host, self.port = host_n_port
                self.port = int(self.port)

            self.path = f"/{'/'.join(path_list[3:])}"

        elif self.path.find(":") != -1:
            self.host, self.port =  self.path.split(":")
            self.port = int(self.port)


    def header(self):
        raw_split = self.raw_split[1:]
        _header = dict()
        for line in raw_split:
            if not line:
                continue
            try:
                broken_line = line.decode().split(":")
                _header[broken_line[0].lower()] = ":".join(broken_line[1:])
            except:
                continue
            
        return _header

class Response:
    def __init__(self, raw:bytes):
        self.raw = raw
        self.raw_split = raw.split(b"\r\n")
        self.log = self.raw_split[0]

        try:
            self.protocol, self.status, self.status_str = self.log.decode().split(" ")
        except Exception as e:
            self.protocol, self.status, self.status_str = ("", "", "")

class ConnectionHandle(threading.Thread):
    def __init__(self, connection, client_addr, username, password):
        super().__init__()
        self.client_conn = connection
        self.client_addr = client_addr
        self.username = username
        self.password = password
        
    def authenticate(self, req):
        if self.username and self.password:
            auth_header = req.header().get('proxy-authorization', '')
            if auth_header.startswith(' Basic'):
                encoded_creds = auth_header.split()[1]
                decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
                provided_username, provided_password = decoded_creds.split(':', 1)
                return provided_username == self.username and provided_password == self.password
            else:
                return False
        else:
            return True

    def remove_proxy_headers(self, raw_request):
        """
        Remove os cabeçalhos Proxy-Connection e Proxy-Authorization do pedido HTTP.
        """
        lines = raw_request.split(b"\r\n")
        updated_lines = []
        for line in lines:
            if not line.startswith(b"Proxy-Connection:") and not line.startswith(b"Proxy-Authorization:"):
                updated_lines.append(line)
        return b"\r\n".join(updated_lines)
    
    def check_login_rate_limit(self):
        """
        Check if the client IP has exceeded the login rate limit.
        """
        client_ip = self.client_addr[0]
        current_time = time.time()

        if client_ip in login_attempts:
            attempts, first_attempt_time = login_attempts[client_ip]
            if current_time - first_attempt_time > LOGIN_RATE_PERIOD:
                # Reset login rate limit after the period has passed
                login_attempts[client_ip] = (1, current_time)
                return True
            elif attempts < LOGIN_RATE_LIMIT:
                # Increment the login attempt count within the current period
                login_attempts[client_ip] = (attempts + 1, first_attempt_time)
                return True
            else:
                # Login rate limit exceeded
                return False
        else:
            # New client IP, initialize login rate limiting
            login_attempts[client_ip] = (1, current_time)
            return True

    def run(self):
        rawreq = self.client_conn.recv(MAX_CHUNK_SIZE)
        if not rawreq:
            return

        req = Request(rawreq)

        if req.protocol == Protocol.http20:
            self.client_conn.send(Error.STATUS_505)
            self.client_conn.close()
            return

        if req.host in BLACKLISTED:
            self.client_conn.send(StaticResponse.block_response)
            self.client_conn.close()
            logg.info(f"{req.method:<8} {req.path} {req.protocol} BLOCKED")
            return

        if not self.check_login_rate_limit():
            self.client_conn.send(Error.STATUS_429)
            self.client_conn.close()
            logg.info(f"Login rate limit exceeded for {self.client_addr[0]}")
            return

        if not self.authenticate(req):
            response = b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            response += b"Proxy-Authenticate: Basic realm=\"Proxy Authentication Required\"\r\n"
            response += b"\r\n"
            self.client_conn.send(response)
            self.client_conn.close()
            return

        self.server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.server_conn.connect((req.host, req.port))
        except Exception as e:
            self.client_conn.send(Error.STATUS_503)
            self.client_conn.close()
            return

        self.client_conn.send(StaticResponse.connection_established)
        self.server_conn.send(self.remove_proxy_headers(req.raw))

        self.server_conn.setblocking(0)
        self.client_conn.setblocking(0)

        res = None

        while True:
            try:
                ready = select.select([self.client_conn, self.server_conn], [], [])[0]
                if self.client_conn in ready:
                    data = self.client_conn.recv(MAX_CHUNK_SIZE)
                    if not data:
                        break
                    self.server_conn.send(data)
                if self.server_conn in ready:
                    data = self.server_conn.recv(MAX_CHUNK_SIZE)
                    res = Response(data)
                    if not data:
                        break
                    self.client_conn.send(data)
            except Exception as e:
                break

        if res:
            logg.info(f"{req.method:<8} {req.path} {req.protocol} {res.status} {res.status_str} {self.client_addr[0]}")

        self.client_conn.close()
        self.server_conn.close()

def start_server(addr="0.0.0.0", port=8080, username=None, password=None):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((addr, port))
    server.listen(BACKLOG)
    logg.info(f"Serving on {addr}:{port}")

    while True:
        if threading.active_count() < MAX_THREADS:
            try:
                conn, addr = server.accept()
                logg.info(f"New connection from {addr}")
                handler = ConnectionHandle(conn, addr, username, password)
                handler.start()
            except KeyboardInterrupt:
                server.close()
                break
            except Exception as e:
                logg.error(f"Error accepting connections: {e}")
                continue

if __name__ == "__main__":
    start_server(
        username="user", 
        password="pass",
        port=80
    )

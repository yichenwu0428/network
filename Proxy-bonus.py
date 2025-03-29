"""
HTTP Proxy Server (Basic + Extended Features)
Feature List:
1. Process GET requests with caching
2. Support 301/302 redirection
3. Parse Cache-Control: max-age
4. Support Expires header validation
5. Preload related resources
6. Handle URLs with port numbers
"""

import socket
import os
import re
import threading
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin, unquote
from email.utils import parsedate_to_datetime

CACHE_DIR = "proxy_cache"
os.makedirs(CACHE_DIR, exist_ok=True)
MAX_REDIRECTS = 5
PRELOAD_DEPTH = 2  # Preloading depth


class ProxyServer:
    def __init__(self, host, port):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(10)
        print(f"[*] Proxy server started on {host}:{port}")

    def start(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(
                target=self.handle_client,
                args=(client_socket,),
                daemon=True
            ).start()

    def handle_client(self, client_socket):
        try:
            request = client_socket.recv(4096).decode()
            if not request:
                return

            # Parse request line
            request_line = request.split('\r\n')[0]
            method, raw_url, _ = request_line.split()

            # Normalize URL
            clean_url = self.normalize_url(raw_url)
            print(f"[*] Request URL: {clean_url}")

            # Process request
            response = self.process_request(clean_url)
            client_socket.sendall(response)

        except ValueError as e:
            client_socket.send(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        except Exception as e:
            print(f"[-] Server error: {str(e)}")
            client_socket.send(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
        finally:
            client_socket.close()

    def process_request(self, url, depth=0):
        """Process request and implement recursive redirection"""
        redirect_count = 0
        current_url = url
        response = None

        while redirect_count < MAX_REDIRECTS:
            # Check cache
            cached_response, expiration = self.check_cache(current_url)
            if cached_response and datetime.now() < expiration:
                print("[+] Using cached response")
                return cached_response

            # Forward request
            try:
                response = self.forward_request(current_url)
            except Exception as e:
                return b"HTTP/1.1 502 Bad Gateway\r\n\r\n"

            # Handle redirection
            if response.startswith((b"HTTP/1.1 301", b"HTTP/1.1 302")):
                redirect_count += 1
                current_url = self.get_redirect_url(response, current_url)
                continue

            # Cache and preload
            if depth < PRELOAD_DEPTH and b"200 OK" in response.splitlines()[0]:
                self.save_to_cache(current_url, response)
                if b"text/html" in response:
                    self.preload_resources(response, current_url, depth + 1)

            return response

        return b"HTTP/1.1 508 Loop Detected\r\n\r\n"

    # ---------- Core Functionality ----------
    def normalize_url(self, raw_url):
        """URL normalization processing"""
        decoded_url = unquote(raw_url)
        decoded_url = re.sub(r"^(http://)+", "http://", decoded_url)

        if not decoded_url.startswith("http://"):
            decoded_url = "http://" + decoded_url.lstrip('/')

        parsed = urlparse(decoded_url)
        if not parsed.netloc:
            raise ValueError("Invalid URL")

        # Handle port numbers (Extended feature 6)
        if ':' in parsed.netloc:
            host, port = parsed.netloc.split(':', 1)
            if not port.isdigit():
                raise ValueError("Invalid port number")

        return decoded_url

    def check_cache(self, url):
        """Enhanced cache check (Extended feature 4)"""
        filename = os.path.join(CACHE_DIR, str(hash(url)))
        if not os.path.exists(filename):
            return None, None

        with open(filename, "rb") as f:
            content = f.read()
            cached_time = datetime.fromtimestamp(os.path.getmtime(filename))

        headers = content.split(b"\r\n\r\n")[0].decode()

        # Priority check Expires header
        expires = None
        if 'expires:' in headers.lower():
            expires_str = re.search(r"Expires:\s*([^\r\n]+)", headers, re.IGNORECASE).group(1)
            expires = parsedate_to_datetime(expires_str)

        # Secondary check max-age
        max_age = None
        if 'cache-control:' in headers.lower():
            match = re.search(r"max-age=(\d+)", headers, re.IGNORECASE)
            if match:
                max_age = int(match.group(1))

        # Calculate expiration time
        expiration = None
        if expires:
            expiration = expires
        elif max_age is not None:
            expiration = cached_time + timedelta(seconds=max_age)
        else:
            expiration = cached_time + timedelta(hours=1)  # Default 1 hour

        return (content, expiration) if datetime.now() < expiration else (None, None)

    def preload_resources(self, response, base_url, depth):
        """Resource preloading (Extended feature 5)"""
        print(f"[*] Preloading resources (depth {depth})")
        html_content = response.split(b"\r\n\r\n")[1].decode()

        # Find all resource links
        resources = set()
        for tag in ['href', 'src']:
            resources.update(re.findall(
                fr'{tag}=["\'](.*?)["\']',
                html_content,
                re.IGNORECASE
            ))

        # Initiate preload requests
        for resource in resources:
            full_url = urljoin(base_url, resource)
            try:
                print(f"[*] Preloading: {full_url}")
                self.process_request(full_url, depth)
            except:
                continue

    # ---------- Network Request Handling ----------
    def forward_request(self, url):
        """Request forwarding implementation"""
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"
        port = 80

        # Handle port numbers (Extended feature 6)
        if ':' in host:
            host, port = host.split(':', 1)
            port = int(port)

        try:
            ip = socket.gethostbyname(host)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((ip, port))

                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Connection: close\r\n\r\n"
                )
                s.send(request.encode())

                response = b""
                while True:
                    data = s.recv(4096)
                    if not data: break
                    response += data

                return response
        except Exception as e:
            raise ValueError(f"Request failed: {str(e)}")

    def get_redirect_url(self, response, base_url):
        """Parse redirection address"""
        headers = response.split(b"\r\n\r\n")[0].decode(errors='replace')
        match = re.search(r"Location:\s*([^\r\n]+)", headers, re.IGNORECASE)
        if not match:
            raise ValueError("Missing Location header")

        location = unquote(match.group(1).strip())
        return urljoin(base_url, location)

    def save_to_cache(self, url, response):
        """Save to cache"""
        filename = os.path.join(CACHE_DIR, str(hash(url)))
        with open(filename, "wb") as f:
            f.write(response)


if __name__ == "__main__":
    proxy = ProxyServer('localhost', 8080)
    proxy.start()

"""
HTTP Proxy Server (Basic + Extended Features)
"""

import socket
import os
import re
import threading
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin, unquote

CACHE_DIR = "proxy_cache"
os.makedirs(CACHE_DIR, exist_ok=True)
MAX_REDIRECTS = 10


class ProxyServer:
    def __init__(self, host, port):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(10)
        print(f"[*] Proxy server started at {host}:{port}")

    def start(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"[+] Connection from {addr}")
            threading.Thread(
                target=self.handle_client,
                args=(client_socket,),
                daemon=True
            ).start()

    def handle_client(self, client_socket):
        try:
            # Receive and parse request
            request = client_socket.recv(4096).decode()
            if not request:
                return

            # Extract request line
            request_line = request.split("\r\n")[0]
            parts = request_line.split()
            if len(parts) < 3:
                raise ValueError("Invalid request line")

            method, raw_url, _ = parts

            # URL normalization
            clean_url = self.normalize_url(raw_url)
            print(f"[*] Normalized URL: {clean_url}")

            redirect_count = 0
            current_url = clean_url
            final_response = None

            while redirect_count < MAX_REDIRECTS:
                # Check cache
                cached_response, expiration = self.check_cache(current_url)
                if cached_response and datetime.now() < expiration:
                    print("[+] Using cached response")
                    client_socket.sendall(cached_response)
                    return

                # Request origin server
                print(f"[!] Requesting origin server: {current_url}")
                try:
                    response = self.forward_request(current_url)
                except Exception as e:
                    print(f"[-] Request failed: {str(e)}")
                    client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    return

                # Handle redirects
                if response.startswith((b"HTTP/1.1 301", b"HTTP/1.1 302")):
                    redirect_count += 1
                    try:
                        new_url = self.get_redirect_url(response, current_url)
                        print(f"[!] Redirect #{redirect_count} to {new_url}")
                        current_url = new_url
                        continue
                    except Exception as e:
                        print(f"[-] Redirect handling failed: {str(e)}")
                        client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        return

                # Handle valid response
                if response:
                    if b"200 OK" in response.splitlines()[0]:
                        self.save_to_cache(current_url, response)
                    final_response = response
                    break

            if final_response:
                client_socket.sendall(final_response)
            else:
                client_socket.send(b"HTTP/1.1 508 Loop Detected\r\n\r\n")

        except ValueError as ve:
            print(f"[-] Client error: {str(ve)}")
            client_socket.send(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        except Exception as e:
            print(f"[-] Server error: {str(e)}")
            client_socket.send(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
        finally:
            client_socket.close()

    def normalize_url(self, raw_url):
        """Enhanced URL normalization method"""
        # Decode URL-encoded characters
        decoded_url = unquote(raw_url)

        # Handle multiple protocol prefixes
        clean_url = re.sub(r"^(http://)+", "http://", decoded_url)

        # Handle missing protocol
        if not clean_url.startswith("http://"):
            clean_url = clean_url.lstrip("/")

        # Validate URL format
        parsed = urlparse(clean_url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format: missing hostname")

        return clean_url

    def get_redirect_url(self, response, base_url):
        """Enhanced redirect URL parsing"""
        try:
            headers_part = response.split(b"\r\n\r\n")[0].decode(errors='replace')
            print(f"[DEBUG] Response headers: {headers_part}")

            # Flexible regex matching
            location_match = re.search(
                r"Location:\s*([^\r\n]+)",
                headers_part,
                re.IGNORECASE
            )
            if not location_match:
                raise ValueError("Location header not found")

            location = location_match.group(1).strip()
            print(f"[DEBUG] Raw Location value: {location}")

            # Handle URL encoding
            decoded_location = unquote(location)

            # Construct absolute URL
            if not decoded_location.startswith(("http://", "https://")):
                new_url = urljoin(base_url, decoded_location)
            else:
                new_url = decoded_location

            print(f"[DEBUG] Parsed URL: {new_url}")
            return new_url

        except Exception as e:
            raise ValueError(f"Failed to parse redirect URL: {str(e)}")

    def forward_request(self, url):
        """Enhanced request forwarding method"""
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"
        query = parsed.query
        port = 80

        # Construct full path
        full_path = f"{path}?{query}" if query else path

        # Handle host with port
        if ":" in host:
            host, port_str = host.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                raise ValueError(f"Invalid port number: {port_str}")

        try:
            # DNS resolution
            ip = socket.gethostbyname(host)
            print(f"[NETWORK] Resolved {host} -> {ip}:{port}")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.settimeout(15)
                server_socket.connect((ip, port))

                # Construct standard HTTP request
                request = (
                    f"GET {full_path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )
                print(f"[NETWORK] Sending request:\n{request}")
                server_socket.send(request.encode())

                # Receive response data
                response = b""
                while True:
                    try:
                        data = server_socket.recv(4096)
                        if not data:
                            break
                        response += data
                    except socket.timeout:
                        break

                print(f'[NETWORK] Received response header:\n{response.split(b" ")[0].decode()}')
                return response

        except socket.gaierror:
            raise ValueError(f"DNS resolution failed: {host}")
        except ConnectionRefusedError:
            raise ValueError(f"Connection refused: {host}:{port}")
        except Exception as e:
            raise ValueError(f"Network error: {str(e)}")

    def check_cache(self, url):
        filename = os.path.join(CACHE_DIR, str(hash(url)))
        if not os.path.exists(filename):
            return None, None

        with open(filename, "rb") as f:
            cached_time = datetime.fromtimestamp(os.path.getmtime(filename))
            content = f.read()

        max_age = 3600
        headers = content.split(b"\r\n\r\n")[0].decode().lower()
        match = re.search(r"cache-control:\s*max-age=(\d+)", headers)
        if match:
            try:
                max_age = int(match.group(1))
            except ValueError:
                print("[!] Failed to parse max-age, using default 3600")

        expiration = cached_time + timedelta(seconds=max_age)
        return content, expiration

    def save_to_cache(self, url, response):
        filename = os.path.join(CACHE_DIR, str(hash(url)))
        with open(filename, "wb") as f:
            f.write(response)
        print(f"[+] Cache updated: {filename}")


if __name__ == "__main__":
    proxy = ProxyServer("localhost", 8080)
    proxy.start()

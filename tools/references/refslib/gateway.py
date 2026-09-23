"""Public-web egress broker and a Unix-socket relay for network-none workers.

The broker alone has Docker bridge networking. Source processors have no network
interface except loopback and reach this broker through one dedicated socket.
Resolve and validate every destination, then connect to the exact checked IP;
never ask a second resolver to choose a different address at connection time.
No source content or host credentials enter the broker's filesystem.
"""
import ipaddress
import os
import select
import socket
import socketserver
import subprocess
import sys
import threading
from urllib.parse import urlsplit

MAX_HEADER = 32768
MAX_TRANSFER = 128 * 1024 * 1024


def destination(host, port):
    if not host or port not in (80, 443):
        raise ValueError("unapproved web destination")
    rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not rows or any(not ipaddress.ip_address(row[4][0]).is_global for row in rows):
        raise ValueError("private or special-use destination")
    return rows


def connect_public(host, port):
    rows = destination(host, port)
    last = None
    for family, kind, protocol, _canon, address in rows:
        remote = socket.socket(family, kind, protocol)
        remote.settimeout(15)
        try:
            remote.connect(address)
            return remote
        except OSError as error:
            last = error
            remote.close()
    raise last or OSError("no public destination")


def transfer(one, two):
    total = 0
    while total < MAX_TRANSFER:
        ready, _, _ = select.select([one, two], [], [], 30)
        if not ready:
            return
        for source in ready:
            data = source.recv(min(65536, MAX_TRANSFER - total))
            if not data:
                return
            total += len(data)
            (two if source is one else one).sendall(data)


class Broker(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        try:
            head = bytearray()
            while b"\r\n\r\n" not in head:
                if len(head) >= MAX_HEADER:
                    raise ValueError("oversized proxy header")
                chunk = self.request.recv(1)
                if not chunk:
                    return
                head.extend(chunk)
            lines = bytes(head).decode("iso-8859-1").split("\r\n")
            method, target, version = lines[0].split(" ")
            if version not in ("HTTP/1.0", "HTTP/1.1"):
                raise ValueError("unsupported proxy protocol")
            parsed = urlsplit("//" + target if method == "CONNECT" else target)
            if parsed.username or parsed.password or parsed.fragment:
                raise ValueError("credentials or fragment in proxy target")
            if method == "CONNECT":
                if parsed.path or parsed.port != 443:
                    raise ValueError("CONNECT is restricted to HTTPS")
            elif method not in ("GET", "HEAD") or parsed.scheme != "http":
                raise ValueError("unsupported retrieval method")
            with connect_public(parsed.hostname, parsed.port or 80) as remote:
                if method == "CONNECT":
                    self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                else:
                    # Rebuild the Host header from the validated target. No
                    # request body, proxy credentials, upgrade or pipelining.
                    headers = []
                    for line in lines[1:]:
                        key = line.partition(":")[0].lower()
                        if key in ("host", "connection", "proxy-connection", "proxy-authorization", "content-length", "transfer-encoding", "upgrade"):
                            continue
                        if line:
                            headers.append(line)
                    path = parsed.path or "/"
                    if parsed.query:
                        path += "?" + parsed.query
                    request = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n%s\r\n\r\n" % (
                        method, path, parsed.netloc, "\r\n".join(headers))
                    remote.sendall(request.encode("iso-8859-1"))
                transfer(self.request, remote)
        except (OSError, ValueError):
            try:
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass


class Threads(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False
    slots = threading.BoundedSemaphore(32)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, address)

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class UnixServer(Threads, socketserver.UnixStreamServer):
    pass


class Relay(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as remote:
                remote.connect("/source-egress/proxy.sock")
                transfer(self.request, remote)
        except OSError:
            pass


class RelayServer(Threads, socketserver.TCPServer):
    pass


def main():
    if sys.argv[1] == "broker":
        path = "/source-egress/proxy.sock"
        with UnixServer(path, Broker) as server:
            os.chmod(path, 0o666)
            server.serve_forever()
    elif sys.argv[1] == "relay":
        with RelayServer(("127.0.0.1", 0), Relay) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            proxy = "http://127.0.0.1:%d" % server.server_address[1]
            environment = dict(os.environ)
            for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
                environment[name] = proxy
            environment["NO_PROXY"] = environment["no_proxy"] = ""
            environment["YSONET_SOURCE_PROXY"] = proxy
            command = sys.argv[2:]
            if command and "chromium" in command[0]:
                command[1:1] = ["--proxy-server=" + proxy, "--proxy-bypass-list=<-loopback>",
                                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
            try:
                return subprocess.call(command, env=environment)
            finally:
                server.shutdown()
    else:
        raise ValueError("unsupported gateway mode")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""A minimal WebSocket client, standard library only.

It exists for one reason: the DevTools protocol needs a WebSocket, and the only
alternative for reading a bot-walled page was `--dump-dom`, which is a dead end
on Windows. A browser is a GUI subsystem program there, so its stdout never
reaches a pipe: zero bytes, exit code 0, in old and new headless alike.

Scope is deliberately tiny. It talks to `127.0.0.1` only, sends text frames,
reads text frames, answers a ping, and stops. No compression, no extensions, no
continuation across a closed connection. Anything more would be a WebSocket
library, and this is a transport for one local debugging port.
"""

import base64
import json
import os
import socket
import struct

OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA


class WebSocketError(Exception):
    pass


class WebSocket(object):
    def __init__(self, url, timeout=30):
        if not url.startswith("ws://"):
            raise WebSocketError("only ws:// is supported, refusing " + url[:60])
        rest = url[len("ws://"):]
        hostport, _, path = rest.partition("/")
        host, _, port = hostport.partition(":")
        if host not in ("127.0.0.1", "localhost"):
            # The debugging port is loopback-only by design. Refusing anything
            # else keeps this from becoming a general-purpose network client.
            raise WebSocketError("refusing a non-loopback debugger host: " + host)
        self.timeout = timeout
        self.socket = socket.create_connection((host, int(port or 80)), timeout)
        self.socket.settimeout(timeout)
        self._buffer = b""
        self._handshake(host, port, "/" + path)
        self._next_id = 0

    def _handshake(self, host, port, path):
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%s\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n" % (path, host, port, key)
        )
        self.socket.sendall(request.encode("ascii"))
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = self.socket.recv(4096)
            if not chunk:
                raise WebSocketError("debugger closed the connection during the handshake")
            header += chunk
        head, _, remainder = header.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise WebSocketError("debugger refused the upgrade: "
                                 + head.split(b"\r\n")[0].decode("ascii", "replace"))
        self._buffer = remainder

    # -- framing ---------------------------------------------------------
    def send_text(self, text):
        payload = text.encode("utf-8")
        header = bytearray([0x80 | OPCODE_TEXT])
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < (1 << 16):
            header.append(0x80 | 126)
            header += struct.pack(">H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", length)
        header += mask
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(bytes(header) + masked)

    def recv_text(self):
        """The next text frame, or None when the peer closes."""
        while True:
            opcode, payload = self._frame()
            if opcode == OPCODE_TEXT:
                return payload.decode("utf-8", "replace")
            if opcode == OPCODE_CLOSE:
                return None
            if opcode == OPCODE_PING:
                self._pong(payload)
            # A binary or unknown frame from a debugger is not our business.

    def _frame(self):
        first = self._read(2)
        opcode = first[0] & 0x0F
        masked = bool(first[1] & 0x80)
        length = first[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._read(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._read(8))[0]
        mask = self._read(4) if masked else None
        payload = self._read(length) if length else b""
        if mask:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return opcode, payload

    def _pong(self, payload):
        header = bytearray([0x80 | OPCODE_PONG])
        mask = os.urandom(4)
        header.append(0x80 | len(payload))
        header += mask
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(bytes(header) + masked)

    def _read(self, count):
        while len(self._buffer) < count:
            chunk = self.socket.recv(65536)
            if not chunk:
                raise WebSocketError("debugger closed the connection")
            self._buffer += chunk
        data, self._buffer = self._buffer[:count], self._buffer[count:]
        return data

    # -- CDP -------------------------------------------------------------
    def call(self, method, params=None, session=None, timeout=None):
        """Send one command and return its result, ignoring unrelated events."""
        self._next_id += 1
        message = {"id": self._next_id, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        self.send_text(json.dumps(message))
        deadline = self._next_id
        original = self.socket.gettimeout()
        if timeout:
            self.socket.settimeout(timeout)
        try:
            while True:
                raw = self.recv_text()
                if raw is None:
                    raise WebSocketError("debugger closed while waiting for " + method)
                data = json.loads(raw)
                if data.get("id") == deadline:
                    if "error" in data:
                        raise WebSocketError("%s failed: %s" % (method, data["error"]))
                    return data.get("result") or {}
        finally:
            self.socket.settimeout(original)

    def close(self):
        try:
            self.socket.close()
        except OSError:
            pass

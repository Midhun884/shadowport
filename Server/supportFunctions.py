import hashlib
import os
import socket
import struct
import threading
from typing import Any

YAMUX_VERSION = 0
YAMUX_TYPE_DATA = 0
YAMUX_TYPE_WINDOW_UPDATE = 1
YAMUX_TYPE_PING = 2
YAMUX_TYPE_GOAWAY = 3
YAMUX_FLAG_SYN = 0x01
YAMUX_FLAG_ACK = 0x02
YAMUX_FLAG_FIN = 0x04
YAMUX_FLAG_RST = 0x08
YAMUX_STREAM_ID = 1
YAMUX_INITIAL_WINDOW = 6 * 1024 * 1024


def require_cipher() -> Any:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        try:
            from cryptography.hazmat.decrepit.ciphers import modes
        except ModuleNotFoundError:
            from cryptography.hazmat.primitives.ciphers import modes
    except ModuleNotFoundError as exc:
        raise RuntimeError("Install dependency first: python -m pip install cryptography") from exc
    return Cipher, algorithms, modes


def read_exact(sock: Any, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("connection closed while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_yamux_frame(sock: Any) -> tuple[int, int, int, int, bytes]:
    header = read_exact(sock, 12)
    version, frame_type, flags, stream_id, length = struct.unpack(">BBHII", header)
    if version != YAMUX_VERSION:
        raise ValueError(f"unsupported yamux version: {version}")
    payload = read_exact(sock, length) if frame_type == YAMUX_TYPE_DATA and length else b""
    return frame_type, flags, stream_id, length, payload


class CryptoStream:
    """AES-128-CFB wrapper for the control channel."""

    def __init__(self, stream: Any, key: bytes) -> None:
        Cipher, algorithms, modes = require_cipher()
        aes_key = hashlib.pbkdf2_hmac("sha1", key, b"midhun-link", 64, 16)
        self.stream = stream
        self.Cipher = Cipher
        self.algorithms = algorithms
        self.modes = modes
        self.key = aes_key
        self.encryptor = None
        self.decryptor = None
        self.read_buffer = bytearray()

    def sendall(self, data: bytes) -> None:
        if self.encryptor is None:
            iv = os.urandom(16)
            cipher = self.Cipher(self.algorithms.AES(self.key), self.modes.CFB(iv))
            self.encryptor = cipher.encryptor()
            self.stream.sendall(iv)
        self.stream.sendall(self.encryptor.update(data))

    def recv(self, size: int) -> bytes:
        if self.decryptor is None:
            iv = read_exact(self.stream, 16)
            cipher = self.Cipher(self.algorithms.AES(self.key), self.modes.CFB(iv))
            self.decryptor = cipher.decryptor()
        while not self.read_buffer:
            chunk = self.stream.recv(max(size, 4096))
            if not chunk:
                return b""
            self.read_buffer.extend(self.decryptor.update(chunk))
        out = bytes(self.read_buffer[:size])
        del self.read_buffer[:size]
        return out

    def close(self) -> None:
        self.stream.close()


class PrependStream:
    def __init__(self, stream: Any, prefix: bytes) -> None:
        self.stream = stream
        self.buffer = bytearray(prefix)

    def recv(self, size: int) -> bytes:
        if self.buffer:
            out = bytes(self.buffer[:size])
            del self.buffer[:size]
            return out
        return self.stream.recv(size)

    def sendall(self, data: bytes) -> None:
        self.stream.sendall(data)

    def settimeout(self, timeout: float | None) -> None:
        self.stream.settimeout(timeout)

    def close(self) -> None:
        self.stream.close()

    def shutdown(self, how: int) -> None:
        self.stream.shutdown(how)


class YamuxServerStream:
    """Tiny server-side yamux stream for the paired client's single stream."""

    def __init__(self, sock: Any, first_frame: tuple[int, int, int, int, bytes]) -> None:
        self.sock = sock
        self.buffer = bytearray()
        self.closed = False
        frame_type, flags, stream_id, length, payload = first_frame
        if (
            frame_type != YAMUX_TYPE_WINDOW_UPDATE
            or not (flags & YAMUX_FLAG_SYN)
            or stream_id != YAMUX_STREAM_ID
        ):
            raise ValueError("expected yamux stream open frame")
        self._write_frame(
            YAMUX_TYPE_WINDOW_UPDATE,
            YAMUX_FLAG_ACK,
            YAMUX_STREAM_ID,
            YAMUX_INITIAL_WINDOW,
            b"",
        )

    def recv(self, size: int) -> bytes:
        while not self.buffer:
            self._read_next_frame()
        out = bytes(self.buffer[:size])
        del self.buffer[:size]
        return out

    def sendall(self, data: bytes) -> None:
        chunk_size = 16 * 1024
        for offset in range(0, len(data), chunk_size):
            chunk = data[offset : offset + chunk_size]
            self._write_frame(YAMUX_TYPE_DATA, 0, YAMUX_STREAM_ID, len(chunk), chunk)

    def settimeout(self, timeout: float | None) -> None:
        self.sock.settimeout(timeout)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self._write_frame(YAMUX_TYPE_DATA, YAMUX_FLAG_FIN, YAMUX_STREAM_ID, 0, b"")
        except OSError:
            pass
        self.sock.close()

    def shutdown(self, how: int) -> None:
        self.sock.shutdown(how)

    def _write_frame(
        self,
        frame_type: int,
        flags: int,
        stream_id: int,
        length: int,
        payload: bytes,
    ) -> None:
        header = struct.pack(">BBHII", YAMUX_VERSION, frame_type, flags, stream_id, length)
        self.sock.sendall(header + payload)

    def _read_next_frame(self) -> None:
        frame_type, flags, stream_id, length, payload = read_yamux_frame(self.sock)
        if frame_type == YAMUX_TYPE_DATA and stream_id == YAMUX_STREAM_ID:
            if flags & YAMUX_FLAG_RST:
                raise EOFError("yamux stream reset")
            if payload:
                self.buffer.extend(payload)
            if flags & YAMUX_FLAG_FIN and not payload:
                raise EOFError("yamux stream closed")
            return
        if frame_type == YAMUX_TYPE_PING and not (flags & YAMUX_FLAG_ACK):
            self._write_frame(YAMUX_TYPE_PING, YAMUX_FLAG_ACK, 0, length, b"")
            return
        if frame_type == YAMUX_TYPE_GOAWAY:
            raise EOFError("yamux session closed")


class ProxyState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.control: CryptoStream | None = None
        self.run_id = ""
        self.proxy_name = ""
        self.pending_users: list[socket.socket] = []
        self.remote_listener: socket.socket | None = None


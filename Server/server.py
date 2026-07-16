
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from supportFunctions import *

TYPE_LOGIN = b"o"
TYPE_LOGIN_RESP = b"1"
TYPE_NEW_PROXY = b"p"
TYPE_NEW_PROXY_RESP = b"2"
TYPE_NEW_WORK_CONN = b"w"
TYPE_REQ_WORK_CONN = b"r"
TYPE_START_WORK_CONN = b"s"

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

TYPE_NAMES = {
    b"o": "Login",
    b"1": "LoginResp",
    b"p": "NewProxy",
    b"2": "NewProxyResp",
    b"w": "NewWorkConn",
    b"r": "ReqWorkConn",
    b"s": "StartWorkConn",
}


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


def require_x509() -> Any:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ModuleNotFoundError as exc:
        raise RuntimeError("Install dependency first: python -m pip install cryptography") from exc
    return x509, hashes, serialization, rsa, NameOID



def auth_key(token: str, timestamp: int) -> str:
    return hashlib.md5(f"{token}{timestamp}".encode("utf-8")).hexdigest()


def omit_empty(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            cleaned = omit_empty(item)
            if cleaned not in ("", None, False, 0, [], {}):
                out[key] = cleaned
        return out
    if isinstance(value, list):
        cleaned_items = [omit_empty(item) for item in value]
        return [item for item in cleaned_items if item not in (None, {}, [])]
    return value


def write_msg(sock: Any, type_byte: bytes, payload: dict[str, Any]) -> None:
    content = json.dumps(omit_empty(payload), separators=(",", ":")).encode("utf-8")
    sock.sendall(type_byte + struct.pack(">q", len(content)) + content)


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


def read_msg(sock: Any) -> tuple[bytes, dict[str, Any]]:
    type_byte = read_exact(sock, 1)
    length = struct.unpack(">q", read_exact(sock, 8))[0]
    if length < 0 or length > 10 * 1024 * 1024:
        raise ValueError(f"invalid tunnel message length: {length}")
    payload = json.loads(read_exact(sock, length).decode("utf-8"))
    return type_byte, payload


def read_yamux_frame(sock: Any) -> tuple[int, int, int, int, bytes]:
    header = read_exact(sock, 12)
    version, frame_type, flags, stream_id, length = struct.unpack(">BBHII", header)
    if version != YAMUX_VERSION:
        raise ValueError(f"unsupported yamux version: {version}")
    payload = read_exact(sock, length) if frame_type == YAMUX_TYPE_DATA and length else b""
    return frame_type, flags, stream_id, length, payload


def detect_stream(sock: ssl.SSLSocket) -> tuple[Any, bool]:
    first = read_exact(sock, 1)
    if first == b"\x00":
        rest = read_exact(sock, 11)
        version, frame_type, flags, stream_id, length = struct.unpack(">BBHII", first + rest)
        payload = read_exact(sock, length) if frame_type == YAMUX_TYPE_DATA and length else b""
        return YamuxServerStream(sock, (frame_type, flags, stream_id, length, payload)), True
    return PrependStream(sock, first), False


def relay_streams(left: Any, right: Any) -> None:
    def pump(src: Any, dst: Any) -> None:
        try:
            while True:
                data = src.recv(32 * 1024)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for item in (src, dst):
                try:
                    item.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    item.close()
                except Exception:
                    pass

    threading.Thread(target=pump, args=(left, right), daemon=True).start()
    threading.Thread(target=pump, args=(right, left), daemon=True).start()


def make_ssl_context() -> ssl.SSLContext:
    x509, hashes, serialization, rsa, NameOID = require_x509()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "midhun-link-server"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    temp_dir = tempfile.TemporaryDirectory()
    cert_path = os.path.join(temp_dir.name, "cert.pem")
    key_path = os.path.join(temp_dir.name, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    context._temp_dir = temp_dir  # type: ignore[attr-defined]
    return context


def accept_tls(raw: socket.socket, context: ssl.SSLContext) -> ssl.SSLSocket:
    first = raw.recv(1, socket.MSG_PEEK)
    if first == b"\x17":
        raw.recv(1)
    return context.wrap_socket(raw, server_side=True)


def verify_login(login_msg: dict[str, Any], token: str) -> str:
    timestamp = int(login_msg.get("timestamp", 0))
    expected = auth_key(token, timestamp)
    got = str(login_msg.get("privilege_key", ""))
    if not secrets.compare_digest(expected, got):
        raise ValueError("login token mismatch")
    return secrets.token_hex(8)


def start_remote_listener(
    state: ProxyState,
    bind_addr: str,
    remote_port: int,
) -> str:
    with state.lock:
        previous_listener = state.remote_listener
        state.remote_listener = None
        state.pending_users.clear()
    if previous_listener is not None:
        try:
            previous_listener.close()
        except OSError:
            pass

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind_addr, remote_port))
    listener.listen(128)
    with state.lock:
        state.remote_listener = listener

    def accept_loop() -> None:
        while True:
            try:
                user_conn, user_addr = listener.accept()
            except OSError:
                return
            with state.lock:
                control = state.control
            if control is None:
                user_conn.close()
                continue
            with state.lock:
                state.pending_users.append(user_conn)
            print(f"Remote user connected from {user_addr[0]}:{user_addr[1]}")
            try:
                write_msg(control, TYPE_REQ_WORK_CONN, {})
            except OSError as exc:
                print(f"Failed to request work connection: {exc}", file=sys.stderr)
                user_conn.close()

    threading.Thread(target=accept_loop, daemon=True).start()
    return f"{bind_addr}:{remote_port}"


def handle_control(
    stream: Any,
    token: str,
    state: ProxyState,
    bind_addr: str,
) -> None:
    type_byte, login_msg = read_msg(stream)
    if type_byte != TYPE_LOGIN:
        raise ValueError(f"expected Login, got {TYPE_NAMES.get(type_byte, type_byte)!r}")

    run_id = verify_login(login_msg, token)
    write_msg(stream, TYPE_LOGIN_RESP, {"version": "midhun-link-server/0.1", "run_id": run_id})
    print(f"Client logged in: run_id={run_id}")

    control = CryptoStream(stream, token.encode("utf-8"))
    with state.lock:
        state.control = control
        state.run_id = run_id

    while True:
        msg_type, payload = read_msg(control)
        if msg_type != TYPE_NEW_PROXY:
            print(f"Control received {TYPE_NAMES.get(msg_type, msg_type)!r}: {payload}")
            continue

        if payload.get("proxy_type") != "tcp":
            write_msg(control, TYPE_NEW_PROXY_RESP, {
                "proxy_name": str(payload.get("proxy_name", "")),
                "error": "only tcp proxy is supported",
            })
            continue

        proxy_name = str(payload.get("proxy_name", ""))
        remote_port = int(payload.get("remote_port", 0))
        try:
            remote_addr = start_remote_listener(state, bind_addr, remote_port)
            state.proxy_name = proxy_name
            write_msg(control, TYPE_NEW_PROXY_RESP, {
                "proxy_name": proxy_name,
                "remote_addr": remote_addr,
            })
            print(f"Proxy started: {proxy_name} listening on {remote_addr}")
        except OSError as exc:
            write_msg(control, TYPE_NEW_PROXY_RESP, {
                "proxy_name": proxy_name,
                "error": str(exc),
            })


def handle_work(stream: Any, state: ProxyState) -> None:
    type_byte, payload = read_msg(stream)
    if type_byte != TYPE_NEW_WORK_CONN:
        raise ValueError(f"expected NewWorkConn, got {TYPE_NAMES.get(type_byte, type_byte)!r}")

    with state.lock:
        user_conn = state.pending_users.pop(0) if state.pending_users else None
        proxy_name = state.proxy_name

    if user_conn is None:
        write_msg(stream, TYPE_START_WORK_CONN, {"error": "no pending user connection"})
        stream.close()
        return

    write_msg(stream, TYPE_START_WORK_CONN, {"proxy_name": proxy_name})
    relay_streams(user_conn, stream)


def handle_client(raw: socket.socket, context: ssl.SSLContext, token: str, state: ProxyState, bind_addr: str) -> None:
    try:
        tls_conn = accept_tls(raw, context)
        stream, is_mux = detect_stream(tls_conn)
        msg_type = read_exact(stream, 1)
        stream = PrependStream(stream, msg_type)

        if msg_type == TYPE_LOGIN:
            handle_control(stream, token, state, bind_addr)
        elif msg_type == TYPE_NEW_WORK_CONN:
            handle_work(stream, state)
        else:
            raise ValueError(f"unexpected first message type: {msg_type!r}")
    except Exception as exc:
        print(f"Connection error: {exc}", file=sys.stderr)
        try:
            raw.close()
        except OSError:
            pass


def serve(bind_addr: str, bind_port: int, token: str, remote_bind_addr: str) -> None:
    require_cipher()
    context = make_ssl_context()
    state = ProxyState()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind_addr, bind_port))
    listener.listen(128)
    print(f"Midhun Link server listening on {bind_addr}:{bind_port}")

    while True:
        raw, addr = listener.accept()
        print(f"Client connection from {addr[0]}:{addr[1]}")
        threading.Thread(
            target=handle_client,
            args=(raw, context, token, state, remote_bind_addr),
            daemon=True,
        ).start()


EMBEDDED_CONFIG = {
    "bindAddr": "0.0.0.0",
    "bindPort": 7000,
    "remoteBindAddr": "0.0.0.0",
    "auth": {
        "token": "SuperSecretPassword123",
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Standalone Python v1 TCP tunnel server.")
    parser.add_argument("--bind-addr", default=EMBEDDED_CONFIG["bindAddr"])
    parser.add_argument("--bind-port", type=int, default=EMBEDDED_CONFIG["bindPort"])
    parser.add_argument("--remote-bind-addr", default=EMBEDDED_CONFIG["remoteBindAddr"])
    parser.add_argument("--token", default=EMBEDDED_CONFIG["auth"]["token"])
    args = parser.parse_args()

    try:
        serve(args.bind_addr, args.bind_port, args.token, args.remote_bind_addr)
    except KeyboardInterrupt:
        print("stopped")
        return 0
    except Exception as exc:
        print(f"server failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

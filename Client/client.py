#!/usr/bin/env python3


from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import ssl
import struct
import sys
import threading
import time
from pathlib import Path
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
    b"1": "LoginResp",
    b"2": "NewProxyResp",
    b"r": "ReqWorkConn",
    b"4": "Pong",
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
        raise RuntimeError(
            "Full proxy mode needs AES-CFB support. Install it with: "
            "python -m pip install cryptography"
        ) from exc
    return Cipher, algorithms, modes


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    try:
        return int(value)
    except ValueError:
        return value


def _set_dotted(root: dict[str, Any], dotted_key: str, value: Any) -> None:
    current = root
    parts = dotted_key.split(".")
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def _simple_toml_load(text: str) -> dict[str, Any]:
    """Tiny fallback parser for common TOML config files on Python < 3.11."""
    data: dict[str, Any] = {}
    current: dict[str, Any] = data

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "[[proxies]]":
            proxy: dict[str, Any] = {}
            data.setdefault("proxies", []).append(proxy)
            current = proxy
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]")
            current = data
            for part in section.split("."):
                current = current.setdefault(part, {})
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        _set_dotted(current, key.strip(), _parse_scalar(value))

    return data


def load_toml(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        import tomllib
    except ModuleNotFoundError:
        return _simple_toml_load(text)

    return tomllib.loads(text)


def cfg_get(cfg: dict[str, Any], dotted_key: str, default: Any = None) -> Any:
    current: Any = cfg
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def omit_empty(value: Any) -> Any:
    """Approximate Go json `omitempty` for the fields we send."""
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


def auth_key(token: str, timestamp: int) -> str:
    return hashlib.md5(f"{token}{timestamp}".encode("utf-8")).hexdigest()


def write_msg(sock: Any, type_byte: bytes, payload: dict[str, Any]) -> None:
    content = json.dumps(
        omit_empty(payload),
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    sock.sendall(type_byte + struct.pack(">q", len(content)) + content)


def read_exact(sock: Any, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("connection closed while reading tunnel message")
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


def open_server_socket(
    cfg: dict[str, Any],
    timeout: float,
    custom_tls_first_byte: bool = False,
) -> socket.socket:
    server_addr = str(cfg.get("serverAddr", "127.0.0.1"))
    server_port = int(cfg.get("serverPort", 7000))
    raw = socket.create_connection((server_addr, server_port), timeout=timeout)

    tls_enable = bool(cfg_get(cfg, "transport.tls.enable", False))
    if not tls_enable:
        return raw

    if custom_tls_first_byte:
        raw.sendall(b"\x17")

    server_name = str(cfg_get(cfg, "transport.tls.serverName", server_addr))
    context = ssl.create_default_context()
    trusted_ca = cfg_get(cfg, "transport.tls.trustedCaFile")
    if trusted_ca:
        context.load_verify_locations(cafile=str(trusted_ca))
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    cert_file = cfg_get(cfg, "transport.tls.certFile")
    key_file = cfg_get(cfg, "transport.tls.keyFile")
    if cert_file and key_file:
        context.load_cert_chain(str(cert_file), str(key_file))

    return context.wrap_socket(raw, server_hostname=server_name)


def build_login(cfg: dict[str, Any]) -> dict[str, Any]:
    timestamp = int(time.time())
    token = str(cfg_get(cfg, "auth.token", cfg.get("token", "")))
    return {
        "version": "midhun-link-client/0.1",
        "hostname": socket.gethostname(),
        "os": platform.system().lower(),
        "arch": platform.machine().lower(),
        "user": str(cfg.get("user", "")),
        "privilege_key": auth_key(token, timestamp),
        "timestamp": timestamp,
        "run_id": "",
        "client_id": str(cfg.get("clientID", "")),
        "metas": cfg.get("metadatas", {}),
        "pool_count": int(cfg_get(cfg, "transport.poolCount", 1)),
    }


def first_proxy(cfg: dict[str, Any]) -> dict[str, Any]:
    proxies = cfg.get("proxies", [])
    if not proxies:
        raise ValueError("embedded config has no proxies")
    return proxies[0]


def build_new_proxy(proxy: dict[str, Any]) -> dict[str, Any]:
    return {
        "proxy_name": str(proxy["name"]),
        "proxy_type": str(proxy.get("type", "tcp")),
        "remote_port": int(proxy["remotePort"]),
    }


def build_new_work_conn(cfg: dict[str, Any], run_id: str) -> dict[str, Any]:
    msg = {
        "run_id": run_id,
    }
    scopes = cfg_get(cfg, "auth.additionalScopes", [])
    if "NewWorkConns" in scopes:
        timestamp = int(time.time())
        token = str(cfg_get(cfg, "auth.token", cfg.get("token", "")))
        msg["timestamp"] = timestamp
        msg["privilege_key"] = auth_key(token, timestamp)
    return msg


def relay_streams(left: socket.socket, right: Any) -> None:
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

    t1 = threading.Thread(target=pump, args=(left, right), daemon=True)
    t2 = threading.Thread(target=pump, args=(right, left), daemon=True)
    t1.start()
    t2.start()


def handle_work_conn(
    cfg: dict[str, Any],
    run_id: str,
    timeout: float,
    custom_tls_first_byte: bool,
    tcp_mux: bool,
) -> None:
    proxy = first_proxy(cfg)
    work = None
    local = None
    try:
        work = connect_message_stream(cfg, timeout, custom_tls_first_byte, tcp_mux)
        write_msg(work, TYPE_NEW_WORK_CONN, build_new_work_conn(cfg, run_id))
        type_byte, payload = read_msg(work)
        if type_byte != TYPE_START_WORK_CONN:
            raise ValueError(f"expected StartWorkConn, got {TYPE_NAMES.get(type_byte, type_byte)!r}")
        if payload.get("error"):
            raise RuntimeError(f"StartWorkConn error: {payload['error']}")

        local_ip = str(proxy.get("localIP", "127.0.0.1"))
        local_port = int(proxy["localPort"])
        local = socket.create_connection((local_ip, local_port), timeout=timeout)
        print(f"Relaying {payload.get('proxy_name', proxy['name'])} to {local_ip}:{local_port}")
        relay_streams(local, work)
    except Exception as exc:
        print(f"Work connection failed: {exc}", file=sys.stderr)
        for item in (work, local):
            if item is not None:
                try:
                    item.close()
                except Exception:
                    pass


def serve_proxy_loop(
    cfg: dict[str, Any],
    control_sock: Any,
    run_id: str,
    timeout: float,
    custom_tls_first_byte: bool,
    tcp_mux: bool,
) -> None:
    token = str(cfg_get(cfg, "auth.token", cfg.get("token", ""))).encode("utf-8")
    control_sock.settimeout(None)
    control = CryptoStream(control_sock, token)
    proxy = first_proxy(cfg)

    write_msg(control, TYPE_NEW_PROXY, build_new_proxy(proxy))
    print(
        "Registered proxy request: "
        f"{proxy['name']} remote:{proxy['remotePort']} -> "
        f"{proxy['localIP']}:{proxy['localPort']}"
    )

    while True:
        type_byte, payload = read_msg(control)
        if type_byte == TYPE_NEW_PROXY_RESP:
            if payload.get("error"):
                raise RuntimeError(f"NewProxyResp error: {payload['error']}")
            print(f"Proxy started: {payload.get('remote_addr', '')}")
            continue
        if type_byte == TYPE_REQ_WORK_CONN:
            threading.Thread(
                target=handle_work_conn,
                args=(cfg, run_id, timeout, custom_tls_first_byte, tcp_mux),
                daemon=True,
            ).start()
            continue
        print(f"Received {TYPE_NAMES.get(type_byte, type_byte.decode('latin1'))}: {payload}")


def login_once(
    cfg: dict[str, Any],
    timeout: float,
    custom_tls_first_byte: bool = False,
    tcp_mux: bool = False,
) -> tuple[Any, bytes, dict[str, Any]]:
    base_sock = open_server_socket(cfg, timeout, custom_tls_first_byte)
    sock: Any = YamuxStream(base_sock) if tcp_mux else base_sock
    sock.settimeout(timeout)
    write_msg(sock, TYPE_LOGIN, build_login(cfg))
    type_byte, payload = read_msg(sock)
    return sock, type_byte, payload


def connect_message_stream(
    cfg: dict[str, Any],
    timeout: float,
    custom_tls_first_byte: bool,
    tcp_mux: bool,
) -> Any:
    base_sock = open_server_socket(cfg, timeout, custom_tls_first_byte)
    sock: Any = YamuxStream(base_sock) if tcp_mux else base_sock
    sock.settimeout(timeout)
    return sock


def login(cfg: dict[str, Any], timeout: float) -> int:
    server_addr = str(cfg.get("serverAddr", "127.0.0.1"))
    server_port = int(cfg.get("serverPort", 7000))
    wire_protocol = str(cfg_get(cfg, "transport.wireProtocol", "v1"))
    protocol = str(cfg_get(cfg, "transport.protocol", "tcp"))

    if protocol != "tcp":
        print(f"Unsupported transport.protocol={protocol!r}; this script supports tcp only.", file=sys.stderr)
        return 2
    if wire_protocol != "v1":
        print(f"Unsupported transport.wireProtocol={wire_protocol!r}; this script supports v1 only.", file=sys.stderr)
        return 2
    print(f"Connecting to Midhun Link server at {server_addr}:{server_port}...")
    attempts = [(False, False)]
    if bool(cfg_get(cfg, "transport.tls.enable", False)):
        attempts.append((True, False))
    attempts.append((False, True))
    if bool(cfg_get(cfg, "transport.tls.enable", False)):
        attempts.append((True, True))

    last_error: Exception | None = None
    control_sock: Any | None = None
    type_byte: bytes | None = None
    payload: dict[str, Any] | None = None
    selected_custom_tls = False
    selected_tcp_mux = False
    for custom_tls_first_byte, tcp_mux in attempts:
        labels = []
        if custom_tls_first_byte:
            labels.append("custom TLS byte")
        if tcp_mux:
            labels.append("yamux")
        if labels:
            print(f"Trying with {', '.join(labels)}...")
        try:
            control_sock, type_byte, payload = login_once(
                cfg,
                timeout,
                custom_tls_first_byte=custom_tls_first_byte,
                tcp_mux=tcp_mux,
            )
            selected_custom_tls = custom_tls_first_byte
            selected_tcp_mux = tcp_mux
            break
        except (EOFError, OSError, ValueError) as exc:
            last_error = exc

    if control_sock is None or type_byte is None or payload is None:
        raise last_error or EOFError("no login response received")

    msg_name = TYPE_NAMES.get(type_byte, type_byte.decode("latin1"))
    print(f"Received {msg_name}: {json.dumps(payload, separators=(',', ':'))}")

    if type_byte != TYPE_LOGIN_RESP:
        print("Server did not return LoginResp.", file=sys.stderr)
        return 1
    if payload.get("error"):
        print(f"Login failed: {payload['error']}", file=sys.stderr)
        return 1

    print(f"Login OK. RunID: {payload.get('run_id', '')}")
    serve_proxy_loop(
        cfg,
        control_sock,
        str(payload.get("run_id", "")),
        timeout,
        selected_custom_tls,
        selected_tcp_mux,
    )
    return 0


EMBEDDED_CONFIG: dict[str, Any] = {
    "serverAddr": "Ip/Domain",
    "serverPort": 7000,
    "auth": {
        "method": "token",
        "token": "TOKEN",
    },
    "transport": {
        "tls": {
            "enable": True,
        },
    },
    "proxies": [
        {
            "name": "ssh_XQC24OG",
            "type": "tcp",
            "localIP": "127.0.0.1",
            "localPort": 1194,
            "remotePort": 1194,
        },
    ],
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Standalone Python v1 TCP tunnel client."
    )
    parser.add_argument(
        "-c",
        "--config",
        default=None,
        help="optional path to a TOML config; embedded config is used by default",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="connection/read timeout in seconds, default: 10",
    )
    args = parser.parse_args()

    try:
        if args.config:
            config_path = Path(args.config)
            if not config_path.exists():
                print(f"Config file not found: {config_path}", file=sys.stderr)
                return 2
            cfg = load_toml(config_path)
        else:
            cfg = EMBEDDED_CONFIG
        return login(cfg, args.timeout)
    except (OSError, EOFError, ValueError, json.JSONDecodeError) as exc:
        print(f"Connection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

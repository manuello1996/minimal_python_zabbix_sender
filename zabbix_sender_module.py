"""
Drop-in single-file Zabbix sender module.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
import re
import ssl
import struct
from typing import Any, Optional, Sequence
import zlib

ZABBIX_RETURN_REGEX = re.compile(
    r"processed: (\d+); failed: (\d+); total: (\d+); seconds spent: (\d+\.\d+)"
)


class ItemData(dict):
    """
    Dictionary representing a trapper item.
    """

    __slots__ = ["__dict__"]

    def __init__(
        self,
        host: str,
        key: str,
        value: Any,
        clock: Optional[int] = None,
        ns: Optional[int] = None,
    ):
        dict.__init__(self, host=host, key=key, value=value)
        if clock is not None:
            self["clock"] = clock
        if ns is not None:
            self["ns"] = ns


@dataclass
class ZabbixResponse:
    processed: int
    failed: int
    total: int
    seconds_spent: float
    response: str


@dataclass
class SendResult:
    ok: bool
    response: Optional[ZabbixResponse] = None
    error: Optional[str] = None


def _format_sender_error(exc: Exception) -> str:
    message = str(exc).lower()
    if isinstance(exc, ssl.SSLError):
        if "psk" in message or "handshake failure" in message or "decrypt error" in message:
            return (
                "TLS-PSK handshake failed. Check that tls_psk_identity and PSK "
                "exactly match the values configured on the Zabbix host/proxy."
            )
        return "TLS error while connecting to Zabbix."
    if isinstance(exc, TimeoutError):
        return "Connection timed out while contacting Zabbix."
    if isinstance(exc, ConnectionError):
        return "Connection to Zabbix was interrupted before a full response."
    if isinstance(exc, ValueError):
        return f"Invalid sender configuration: {exc}"
    return f"Failed to send metrics to Zabbix: {exc}"


class AsyncSender:
    __slots__ = [
        "server",
        "port",
        "timeout",
        "tls_connect",
        "tls_psk_identity",
        "tls_psk",
        "tls_psk_file",
        "tls_server_name",
    ]

    def __init__(
        self,
        server: str,
        port: int = 10051,
        timeout: Optional[float] = None,
        tls_connect: Optional[str] = None,
        tls_psk_identity: Optional[str] = None,
        tls_psk: Optional[str] = None,
        tls_psk_file: Optional[str] = None,
        tls_server_name: Optional[str] = None,
    ) -> None:
        self.server = server
        self.port = port
        self.timeout = timeout
        self.tls_connect = tls_connect
        self.tls_psk_identity = tls_psk_identity
        self.tls_psk = tls_psk
        self.tls_psk_file = tls_psk_file
        self.tls_server_name = tls_server_name

        self._validate_tls_options()

    def _validate_tls_options(self) -> None:
        if self.tls_connect is None:
            return
        if self.tls_connect != "psk":
            raise ValueError("only tls_connect='psk' is supported")
        if not self.tls_psk_identity:
            raise ValueError("tls_psk_identity is required for PSK")
        if bool(self.tls_psk) == bool(self.tls_psk_file):
            raise ValueError("set exactly one of tls_psk or tls_psk_file for PSK")

    @staticmethod
    def _create_payload(items: Sequence[ItemData]) -> bytes:
        return json.dumps({"request": "sender data", "data": items}).encode("utf-8")

    @staticmethod
    def _create_packet(items: Sequence[ItemData]) -> bytes:
        payload = AsyncSender._create_payload(items)
        return b"ZBXD" + b"\x01" + struct.pack("<II", len(payload), 0) + payload

    @staticmethod
    def _parse_response_header(header: bytes) -> tuple[int, bool]:
        if len(header) != 13:
            raise ValueError("invalid zabbix header size")
        if header[0:4] != b"ZBXD":
            raise ValueError("zabbix header not found or incorrect")

        flags = header[4]
        if not flags & 0x01:
            raise ValueError("invalid zabbix protocol version flag")

        data_len_low, data_len_high = struct.unpack("<II", header[5:])
        response_size = data_len_low + (data_len_high << 32)
        compressed = bool(flags & 0x02)
        return response_size, compressed

    @staticmethod
    def _parse_response(response: bytes) -> ZabbixResponse:
        obj = json.loads(response)
        parsed_data = ZABBIX_RETURN_REGEX.match(obj["info"])
        if parsed_data is None:
            raise ValueError(f"invalid zabbix response info format: {obj['info']}")
        return ZabbixResponse(
            response=obj["response"],
            processed=int(parsed_data.group(1)),
            failed=int(parsed_data.group(2)),
            total=int(parsed_data.group(3)),
            seconds_spent=float(parsed_data.group(4)),
        )

    async def _read_response(self, reader: asyncio.StreamReader) -> ZabbixResponse:
        header = await reader.readexactly(13)
        resp_size, compressed = self._parse_response_header(header)

        data = b""
        while len(data) < resp_size:
            chunk = await reader.read(min(1024, resp_size - len(data)))
            if not chunk:
                raise ConnectionError("connection closed before full response was received")
            data += chunk

        if compressed:
            data = zlib.decompress(data)
        return self._parse_response(data)

    def _parse_psk(self) -> bytes:
        if self.tls_psk_file:
            raw = Path(self.tls_psk_file).read_text(encoding="utf-8").strip()
        else:
            raw = str(self.tls_psk).strip()

        if not raw:
            raise ValueError("PSK cannot be empty")
        try:
            return bytes.fromhex(raw)
        except ValueError as exc:
            raise ValueError("PSK must be a valid hex string") from exc

    def _create_psk_ssl_context(self) -> ssl.SSLContext:
        psk = self._parse_psk()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers("PSK")

        if hasattr(context, "set_psk_client_callback"):
            context.set_psk_client_callback(lambda _hint: (self.tls_psk_identity, psk))
            return context

        try:
            from sslpsk3 import SSLPSKContext  # type: ignore[import-not-found]
        except Exception as exc:
            raise RuntimeError(
                "TLS-PSK requires Python 3.13+ or package 'sslpsk3'"
            ) from exc

        compat_context = SSLPSKContext(ssl.PROTOCOL_TLS)
        compat_context.check_hostname = False
        compat_context.verify_mode = ssl.CERT_NONE
        compat_context.set_ciphers("PSK")
        compat_context.psk = psk
        compat_context.psk_identity = self.tls_psk_identity.encode("utf-8")
        return compat_context

    def _connection_kwargs(self) -> dict:
        kwargs: dict[str, object] = {}
        if self.timeout is not None:
            kwargs["ssl_handshake_timeout"] = self.timeout
        if self.tls_connect == "psk":
            kwargs["ssl"] = self._create_psk_ssl_context()
            kwargs["server_hostname"] = self.tls_server_name or self.server
        return kwargs

    async def send(self, items=None) -> ZabbixResponse:
        if isinstance(items, ItemData):
            items = [items]
        if items is None:
            items = []

        packet = self._create_packet(items)
        reader, writer = await asyncio.open_connection(
            self.server, self.port, **self._connection_kwargs()
        )
        try:
            writer.write(packet)
            await writer.drain()
            return await self._read_response(reader)
        finally:
            writer.close()
            await writer.wait_closed()

    async def send_safe(self, items=None) -> SendResult:
        try:
            return SendResult(ok=True, response=await self.send(items))
        except Exception as exc:
            return SendResult(ok=False, error=_format_sender_error(exc))


async def send_async_safe(
    server: str,
    items,
    port: int = 10051,
    timeout: Optional[float] = None,
    tls_connect: Optional[str] = None,
    tls_psk_identity: Optional[str] = None,
    tls_psk: Optional[str] = None,
    tls_psk_file: Optional[str] = None,
    tls_server_name: Optional[str] = None,
) -> SendResult:
    try:
        sender = AsyncSender(
            server=server,
            port=port,
            timeout=timeout,
            tls_connect=tls_connect,
            tls_psk_identity=tls_psk_identity,
            tls_psk=tls_psk,
            tls_psk_file=tls_psk_file,
            tls_server_name=tls_server_name,
        )
        return await sender.send_safe(items)
    except Exception as exc:
        return SendResult(ok=False, error=_format_sender_error(exc))


__all__ = [
    "ItemData",
    "ZabbixResponse",
    "SendResult",
    "AsyncSender",
    "send_async_safe",
]

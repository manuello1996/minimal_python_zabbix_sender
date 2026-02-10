# Minimal zabbix sender python implementation

This file documents the standalone module `zabbix_sender_module.py`.

## What the module provides

- `ItemData`: payload item for one trapper metric.
- `ZabbixResponse`: parsed Zabbix sender response.
- `SendResult`: safe result wrapper (`ok`, `response`, `error`).
- `AsyncSender`: async sender client with optional TLS-PSK.
- `send_async_safe(...)`: one-call safe async helper.

Supported transport modes:

- Plain TCP (no TLS).
- TLS-PSK with PSK hex value.
- TLS-PSK with PSK file.

## Protocol compatibility

- Uses Zabbix sender framing (`ZBXD\x01` + header + JSON payload).
- Compatible with Zabbix 7.x sender protocol behavior.

## Basic requirements

- Python 3.10+.
- For TLS-PSK on Python < 3.13, install `sslpsk3`.
- Zabbix host must contain matching trapper items.
- For PSK mode, Zabbix host/proxy must be configured with matching:
  - PSK identity
  - PSK value

---

## Example 1: Plain TCP, one metric (safe helper)

```python
import asyncio
from zabbix_sender_module import ItemData, send_async_safe

async def main():
    result = await send_async_safe(
        server="127.0.0.1",
        port=10051,
        items=ItemData(host="sender-test", key="test.trapper.int", value=42),
    )
    if result.ok:
        print(result.response)
    else:
        print("Error:", result.error)

asyncio.run(main())
```

## Example 2: Plain TCP, multiple metrics (safe helper)

```python
import asyncio
from zabbix_sender_module import ItemData, send_async_safe

async def main():
    items = [
        ItemData(host="sender-test", key="test.trapper.int", value=42),
        ItemData(host="sender-test", key="test.trapper.text", value="long text payload"),
    ]
    result = await send_async_safe(server="127.0.0.1", port=10051, items=items)
    print(result.response if result.ok else result.error)

asyncio.run(main())
```

## Example 3: TLS-PSK with inline hex PSK (safe helper)

```python
import asyncio
from zabbix_sender_module import ItemData, send_async_safe

async def main():
    result = await send_async_safe(
        server="127.0.0.1",
        port=10051,
        items=ItemData(host="sender-test", key="test.trapper.int", value=42),
        tls_connect="psk",
        tls_psk_identity="sender-test-psk",
        tls_psk="00112233445566778899AABBCCDDEEFF",
    )
    print(result.response if result.ok else result.error)

asyncio.run(main())
```

## Example 4: TLS-PSK with PSK file (safe helper)

```python
import asyncio
from zabbix_sender_module import ItemData, send_async_safe

async def main():
    result = await send_async_safe(
        server="127.0.0.1",
        port=10051,
        items=ItemData(host="sender-test", key="test.trapper.int", value=42),
        tls_connect="psk",
        tls_psk_identity="sender-test-psk",
        tls_psk_file="/etc/zabbix/zabbix_agent2.psk",
    )
    print(result.response if result.ok else result.error)

asyncio.run(main())
```

## Example 5: Class-based usage with explicit error handling

```python
import asyncio
from zabbix_sender_module import AsyncSender, ItemData

async def main():
    sender = AsyncSender("127.0.0.1", 10051)
    try:
        response = await sender.send(
            [
                ItemData(host="sender-test", key="test.trapper.int", value=42),
                ItemData(host="sender-test", key="test.trapper.text", value="text"),
            ]
        )
        print(response)
    except Exception as exc:
        print("Send failed:", exc)

asyncio.run(main())
```

## Example 6: Class-based safe send (`send_safe`)

```python
import asyncio
from zabbix_sender_module import AsyncSender, ItemData

async def main():
    sender = AsyncSender(
        "127.0.0.1",
        10051,
        tls_connect="psk",
        tls_psk_identity="sender-test-psk",
        tls_psk="00112233445566778899AABBCCDDEEFF",
    )
    result = await sender.send_safe(ItemData("sender-test", "test.trapper.int", 42))
    print(result.response if result.ok else result.error)

asyncio.run(main())
```

## Example 7: Item with custom timestamp (`clock` and `ns`)

```python
import asyncio
import time
from zabbix_sender_module import ItemData, send_async_safe

async def main():
    now = int(time.time())
    result = await send_async_safe(
        server="127.0.0.1",
        port=10051,
        items=ItemData(
            host="sender-test",
            key="test.trapper.int",
            value=42,
            clock=now,
            ns=123000000,
        ),
    )
    print(result.response if result.ok else result.error)

asyncio.run(main())
```

---

## Usage notes

- `items` can be either:
  - one `ItemData`, or
  - a list of `ItemData`.
- `send_async_safe(...)` never raises sender errors; it returns `SendResult`.
- `AsyncSender.send(...)` may raise exceptions.
- `AsyncSender.send_safe(...)` catches sender exceptions and returns `SendResult`.

## Common errors

- `TLS-PSK handshake failed...`
  - Identity or PSK mismatch between client and Zabbix config.
- `Invalid sender configuration: ...`
  - Missing `tls_psk_identity`, or invalid PSK setup.
- `Connection timed out...`
  - Wrong server/port or network issue.

---

## Synchronous version

For projects without `asyncio`, use `zabbix_sender_module_sync.py`.

Provided API:

- `ItemData`
- `ZabbixResponse`
- `SendResult`
- `Sender` (sync class)
- `send_safe(...)` (sync helper)

### Example S1: Plain TCP (sync helper)

```python
from zabbix_sender_module_sync import ItemData, send_safe

result = send_safe(
    server="127.0.0.1",
    port=10051,
    items=ItemData(host="sender-test", key="test.trapper.int", value=42),
)
print(result.response if result.ok else result.error)
```

### Example S2: TLS-PSK with inline hex PSK (sync helper)

```python
from zabbix_sender_module_sync import ItemData, send_safe

result = send_safe(
    server="127.0.0.1",
    port=10051,
    items=ItemData(host="sender-test", key="test.trapper.int", value=42),
    tls_connect="psk",
    tls_psk_identity="sender-test-psk",
    tls_psk="00112233445566778899AABBCCDDEEFF",
)
print(result.response if result.ok else result.error)
```

### Example S3: TLS-PSK with PSK file (sync class)

```python
from zabbix_sender_module_sync import ItemData, Sender

sender = Sender(
    "127.0.0.1",
    10051,
    tls_connect="psk",
    tls_psk_identity="sender-test-psk",
    tls_psk_file="/etc/zabbix/zabbix_agent2.psk",
)

result = sender.send_safe(
    [
        ItemData(host="sender-test", key="test.trapper.int", value=42),
        ItemData(host="sender-test", key="test.trapper.text", value="long text payload"),
    ]
)
print(result.response if result.ok else result.error)
```

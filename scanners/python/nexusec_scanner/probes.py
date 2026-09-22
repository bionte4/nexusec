"""TCP connect + optional banner grab probes."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ProbeResult:
    host: str
    port: int
    open: bool
    banner: Optional[str] = None
    error: Optional[str] = None
    latency_ms: Optional[float] = None


async def tcp_probe(
    host: str,
    port: int,
    *,
    timeout: float = 1.5,
    grab_banner: bool = True,
    banner_bytes: int = 128,
) -> ProbeResult:
    started = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001 — probe failures are expected
        return ProbeResult(
            host=host,
            port=port,
            open=False,
            error=type(exc).__name__,
        )

    banner: Optional[str] = None
    try:
        if grab_banner:
            try:
                data = await asyncio.wait_for(reader.read(banner_bytes), timeout=0.4)
                if data:
                    banner = data.decode("utf-8", errors="replace").strip()[:256]
            except Exception:
                banner = None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    latency = (asyncio.get_event_loop().time() - started) * 1000.0
    return ProbeResult(
        host=host,
        port=port,
        open=True,
        banner=banner,
        latency_ms=round(latency, 2),
    )

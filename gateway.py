#!/usr/bin/env python3
"""
Rotating Proxy Gateway — bendjara.duckdns.org:443
Auth: yacin:bendjara | Cooldown: 30 min/IP
Sources: hproxy.com + proxyscrape.com
python-socks[asyncio] + aiohttp
"""

import asyncio
import aiohttp
import base64
import logging
import random
import re
import time
from dataclasses import dataclass, field
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("gateway")

# ── Config ────────────────────────────────────────────────────────────────────
LISTEN_HOST       = "0.0.0.0"
LISTEN_PORT       = 443
PROXY_USER        = "yacin"
PROXY_PASS        = "bendjara"
COOLDOWN_SEC      = 1800          # 30 min per IP
REFRESH_INTERVAL  = 300           # re-fetch + re-test every 5 min
TEST_TIMEOUT      = 6.0           # max seconds for proxy liveness check
TEST_CONCURRENCY  = 80            # parallel testers
CONNECT_TIMEOUT   = 10.0          # upstream connect
PIPE_TIMEOUT      = 45.0          # idle pipe timeout
FAIL_LIMIT        = 3             # failures before blacklist

DUCKDNS_TOKEN     = "ee2ecf47-a75d-46ba-95fb-ef6948751bb8"
DUCKDNS_DOMAIN    = "bendjara"

_EXPECTED_AUTH = base64.b64encode(
    f"{PROXY_USER}:{PROXY_PASS}".encode()
).decode()


# ── Proxy model ───────────────────────────────────────────────────────────────
@dataclass
class Proxy:
    url:       str      # http://ip:port | socks5://ip:port
    ip:        str
    port:      int
    protocol:  str      # http | socks4 | socks5
    latency:   float = 9999.0
    alive:     bool  = False
    last_used: float = 0.0
    failures:  int   = 0

    @property
    def key(self) -> str:
        return f"{self.ip}:{self.port}"

    def on_cooldown(self) -> bool:
        return (time.time() - self.last_used) < COOLDOWN_SEC

    def dead(self) -> bool:
        return self.failures >= FAIL_LIMIT

    def score(self) -> float:
        if self.on_cooldown() or self.dead() or not self.alive:
            return float("inf")
        return self.latency


# ── Proxy pool ────────────────────────────────────────────────────────────────
class ProxyPool:
    def __init__(self):
        self._pool: dict[str, Proxy] = {}
        self._lock = asyncio.Lock()
        self._sem  = asyncio.Semaphore(TEST_CONCURRENCY)

    # ── Fetch: hproxy ─────────────────────────────────────────────────────────
    async def _fetch_hproxy(self, s: aiohttp.ClientSession) -> list[Proxy]:
        try:
            async with s.get(
                "https://hproxy.com/api/proxy-list",
                params={
                    "format":         "json",
                    "protocol":       "http,socks5",
                    "min_uptime_pct": 70,
                    "max_latency_ms": 1000,
                    "sort":           "uptime",
                    "limit":          200,
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as r:
                raw = await r.json(content_type=None)
                # tolerate list or wrapped object
                data = raw if isinstance(raw, list) else raw.get(
                    "data", raw.get("proxies", raw.get("list", []))
                )
                out = []
                for item in data:
                    try:
                        ip    = str(item.get("ip") or item.get("host") or "").strip()
                        port  = int(item.get("port", 0))
                        proto = str(item.get("protocol", "http")).lower().strip()
                        if not ip or not port:
                            continue
                        if proto not in ("http", "https", "socks4", "socks5"):
                            proto = "http"
                        if proto == "https":
                            proto = "http"
                        out.append(Proxy(
                            url=f"{proto}://{ip}:{port}",
                            ip=ip, port=port, protocol=proto
                        ))
                    except Exception:
                        continue
                log.info(f"hproxy → {len(out)} proxies parsed")
                return out
        except Exception as e:
            log.warning(f"hproxy fetch failed: {e}")
            return []

    # ── Fetch: proxyscrape ────────────────────────────────────────────────────
    async def _fetch_proxyscrape(self, s: aiohttp.ClientSession) -> list[Proxy]:
        try:
            async with s.get(
                "https://api.proxyscrape.com/v4/free-proxy-list/get",
                params={
                    "request":       "display_proxies",
                    "proxy_format":  "protocolipport",
                    "format":        "text",
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as r:
                text = await r.text()
                out  = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # protocol://ip:port
                    m = re.match(
                        r"^(https?|socks[45])://(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$",
                        line
                    )
                    if m:
                        proto, ip, port = m.group(1), m.group(2), int(m.group(3))
                    else:
                        # bare ip:port
                        m2 = re.match(
                            r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$", line
                        )
                        if not m2:
                            continue
                        ip, port, proto = m2.group(1), int(m2.group(2)), "http"
                    if proto == "https":
                        proto = "http"
                    out.append(Proxy(
                        url=f"{proto}://{ip}:{port}",
                        ip=ip, port=port, protocol=proto
                    ))
                log.info(f"proxyscrape → {len(out)} proxies parsed")
                return out
        except Exception as e:
            log.warning(f"proxyscrape fetch failed: {e}")
            return []

    # ── Test single proxy ─────────────────────────────────────────────────────
    async def _test(self, proxy: Proxy) -> bool:
        async with self._sem:
            try:
                t0 = time.monotonic()
                if proxy.protocol.startswith("socks"):
                    # TCP tunnel through SOCKS → httpbin.org:80 → GET /ip
                    from python_socks.async_.asyncio import Proxy as SP
                    sock_proxy = SP.from_url(proxy.url)
                    sock = await asyncio.wait_for(
                        sock_proxy.connect("httpbin.org", 80),
                        timeout=TEST_TIMEOUT
                    )
                    rdr, wtr = await asyncio.open_connection(sock=sock)
                    wtr.write(b"GET /ip HTTP/1.0\r\nHost: httpbin.org\r\n\r\n")
                    await wtr.drain()
                    resp = await asyncio.wait_for(rdr.read(256), TEST_TIMEOUT)
                    wtr.close()
                    ok = b"200" in resp
                else:
                    async with aiohttp.ClientSession() as sess:
                        async with sess.get(
                            "http://httpbin.org/ip",
                            proxy=proxy.url,
                            timeout=aiohttp.ClientTimeout(total=TEST_TIMEOUT),
                            allow_redirects=False,
                        ) as resp:
                            ok = resp.status == 200

                if ok:
                    proxy.latency  = round(time.monotonic() - t0, 3)
                    proxy.alive    = True
                    proxy.failures = 0
                    return True
            except Exception:
                pass

            proxy.alive     = False
            proxy.failures += 1
            return False

    # ── Full pool refresh ─────────────────────────────────────────────────────
    async def refresh(self):
        log.info("Pool refresh started …")
        async with aiohttp.ClientSession() as s:
            hp, ps = await asyncio.gather(
                self._fetch_hproxy(s),
                self._fetch_proxyscrape(s),
            )

        all_proxies = hp + ps
        seen:   set[str]   = set()
        unique: list[Proxy] = []
        for p in all_proxies:
            if p.key not in seen:
                seen.add(p.key)
                unique.append(p)

        log.info(f"Testing {len(unique)} unique proxies …")
        results = await asyncio.gather(
            *[self._test(p) for p in unique],
            return_exceptions=True,
        )
        alive = [p for p, r in zip(unique, results) if r is True]
        log.info(f"Alive: {len(alive)}/{len(unique)}")

        async with self._lock:
            for p in alive:
                existing = self._pool.get(p.key)
                if existing:
                    p.last_used = existing.last_used   # preserve cooldown
                self._pool[p.key] = p

            # Prune confirmed-dead proxies not in new batch
            new_keys = {p.key for p in alive}
            dead_keys = [
                k for k, v in self._pool.items()
                if v.dead() and k not in new_keys
            ]
            for k in dead_keys:
                del self._pool[k]

        s = self.stats()
        log.info(
            f"Pool ready — {s['available']} available / "
            f"{s['alive']} alive / {s['total']} total"
        )
        if s["available"] < 10:
            log.warning("Pool critically low — check API connectivity")

    async def _refresh_loop(self):
        while True:
            await asyncio.sleep(REFRESH_INTERVAL)
            try:
                await self.refresh()
            except Exception as e:
                log.error(f"Refresh loop error: {e}")

    async def start(self):
        await self.refresh()
        asyncio.create_task(self._refresh_loop())

    # ── Pick best available proxy ─────────────────────────────────────────────
    async def get(self) -> Optional[Proxy]:
        async with self._lock:
            available = [
                p for p in self._pool.values()
                if p.alive and not p.on_cooldown() and not p.dead()
            ]
            if not available:
                # fallback: ignore cooldown, not dead (graceful degrade)
                available = [
                    p for p in self._pool.values()
                    if p.alive and not p.dead()
                ]
            if not available:
                return None

            available.sort(key=lambda p: p.score())
            # pick randomly from top 10 to spread load
            top  = available[: min(10, len(available))]
            pick = random.choice(top)
            pick.last_used = time.time()
            return pick

    async def mark_fail(self, proxy: Proxy):
        async with self._lock:
            p = self._pool.get(proxy.key)
            if p:
                p.failures += 1
                if p.dead():
                    p.alive = False
                    log.debug(f"Blacklisted: {p.key} ({p.failures} failures)")

    def stats(self) -> dict:
        alive     = sum(1 for p in self._pool.values() if p.alive)
        available = sum(
            1 for p in self._pool.values()
            if p.alive and not p.on_cooldown() and not p.dead()
        )
        return {"total": len(self._pool), "alive": alive, "available": available}


# ── Gateway server ────────────────────────────────────────────────────────────
class GatewayServer:
    def __init__(self, pool: ProxyPool):
        self.pool = pool

    def _auth_ok(self, headers: dict[str, str]) -> bool:
        auth = headers.get("proxy-authorization", "")
        if auth.startswith("Basic "):
            return auth[6:].strip() == _EXPECTED_AUTH
        return False

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        peer = writer.get_extra_info("peername", ("?", 0))
        try:
            first = await asyncio.wait_for(reader.readline(), 10.0)
            if not first:
                return

            raw_headers: list[bytes] = []
            while True:
                line = await asyncio.wait_for(reader.readline(), 10.0)
                if line in (b"\r\n", b"\n", b""):
                    break
                raw_headers.append(line)

            headers: dict[str, str] = {}
            for line in raw_headers:
                if b":" in line:
                    k, _, v = line.partition(b":")
                    headers[k.decode(errors="replace").lower().strip()] = (
                        v.decode(errors="replace").strip()
                    )

            if not self._auth_ok(headers):
                writer.write(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b'Proxy-Authenticate: Basic realm="gateway"\r\n'
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return

            line_str = first.decode(errors="replace").strip()
            method, _, rest = line_str.partition(" ")
            target = rest.split()[0] if rest.strip() else ""

            if method.upper() == "CONNECT":
                await self._handle_connect(target, reader, writer)
            else:
                await self._handle_http(first, raw_headers, headers, reader, writer)

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            log.debug(f"handle [{peer[0]}]: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── CONNECT (HTTPS tunnel) ────────────────────────────────────────────────
    async def _handle_connect(
        self,
        target: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        host, _, port_s = target.rpartition(":")
        port = int(port_s) if port_s.isdigit() else 443

        proxy = await self.pool.get()
        if not proxy:
            writer.write(
                b"HTTP/1.1 503 No Upstream Available\r\nContent-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return

        up_r: Optional[asyncio.StreamReader]  = None
        up_w: Optional[asyncio.StreamWriter]  = None
        try:
            if proxy.protocol.startswith("socks"):
                from python_socks.async_.asyncio import Proxy as SP
                sock_proxy = SP.from_url(proxy.url)
                sock = await asyncio.wait_for(
                    sock_proxy.connect(host, port), CONNECT_TIMEOUT
                )
                up_r, up_w = await asyncio.open_connection(sock=sock)
            else:
                up_r, up_w = await asyncio.wait_for(
                    asyncio.open_connection(proxy.ip, proxy.port),
                    CONNECT_TIMEOUT,
                )
                up_w.write(
                    f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()
                )
                await up_w.drain()
                resp_line = await asyncio.wait_for(up_r.readline(), 10.0)
                if b"200" not in resp_line:
                    raise ConnectionError(
                        f"upstream CONNECT refused: {resp_line.strip()}"
                    )
                # drain remaining headers
                while True:
                    hdr = await asyncio.wait_for(up_r.readline(), 5.0)
                    if hdr in (b"\r\n", b"\n", b""):
                        break

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            await asyncio.gather(
                _pipe(reader,  up_w, PIPE_TIMEOUT),
                _pipe(up_r,  writer, PIPE_TIMEOUT),
                return_exceptions=True,
            )

        except Exception as e:
            log.debug(f"CONNECT {target} via {proxy.key}: {e}")
            await self.pool.mark_fail(proxy)
            try:
                writer.write(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
                )
                await writer.drain()
            except Exception:
                pass
        finally:
            if up_w:
                try:
                    up_w.close()
                    await up_w.wait_closed()
                except Exception:
                    pass

    # ── Plain HTTP ────────────────────────────────────────────────────────────
    async def _handle_http(
        self,
        first: bytes,
        raw_headers: list[bytes],
        headers: dict[str, str],
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        proxy = await self.pool.get()
        if not proxy:
            writer.write(
                b"HTTP/1.1 503 No Upstream Available\r\nContent-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return

        up_r: Optional[asyncio.StreamReader] = None
        up_w: Optional[asyncio.StreamWriter] = None
        try:
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(proxy.ip, proxy.port),
                CONNECT_TIMEOUT,
            )
            up_w.write(first)
            for h in raw_headers:
                if not h.lower().startswith(b"proxy-authorization"):
                    up_w.write(h)
            up_w.write(b"\r\n")

            clen = int(headers.get("content-length", 0))
            if clen > 0:
                body = await reader.read(clen)
                up_w.write(body)
            await up_w.drain()

            await _pipe(up_r, writer, PIPE_TIMEOUT)

        except Exception as e:
            log.debug(f"HTTP via {proxy.key}: {e}")
            await self.pool.mark_fail(proxy)
            try:
                writer.write(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
                )
                await writer.drain()
            except Exception:
                pass
        finally:
            if up_w:
                try:
                    up_w.close()
                    await up_w.wait_closed()
                except Exception:
                    pass


# ── Pipe helper ───────────────────────────────────────────────────────────────
async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: float,
):
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65535), timeout)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass


# ── DuckDNS ───────────────────────────────────────────────────────────────────
async def _duckdns_update():
    url = (
        f"https://www.duckdns.org/update"
        f"?domains={DUCKDNS_DOMAIN}&token={DUCKDNS_TOKEN}&ip="
    )
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                body = (await r.text()).strip()
                if "OK" in body:
                    log.info("DuckDNS: IP updated")
                else:
                    log.warning(f"DuckDNS: unexpected response → {body}")
    except Exception as e:
        log.warning(f"DuckDNS update error: {e}")


async def _duckdns_loop():
    while True:
        await asyncio.sleep(300)   # re-confirm every 5 min
        await _duckdns_update()


# ── Entry ─────────────────────────────────────────────────────────────────────
async def main():
    await _duckdns_update()
    asyncio.create_task(_duckdns_loop())

    pool = ProxyPool()
    await pool.start()

    gateway = GatewayServer(pool)
    server  = await asyncio.start_server(
        gateway.handle, LISTEN_HOST, LISTEN_PORT
    )

    s = pool.stats()
    log.info("=" * 50)
    log.info(f"  Gateway  :  http://bendjara.duckdns.org:{LISTEN_PORT}")
    log.info(f"  Auth     :  {PROXY_USER}:{PROXY_PASS}")
    log.info(f"  Pool     :  {s['available']} available / {s['alive']} alive")
    log.info(f"  Cooldown :  {COOLDOWN_SEC // 60} min per IP")
    log.info("=" * 50)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Gateway stopped.")

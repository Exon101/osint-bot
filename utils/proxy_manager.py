"""
Proxy Manager Module
Handles proxy pool management, rotation strategies, and validation.

Supported proxy types:
  - HTTP / HTTPS
  - SOCKS4
  - SOCKS5

Rotation modes:
  - sequential  — Round-robin through the pool
  - random      — Pick a random proxy each request
  - failover    — Try first proxy, fall back on failure

Usage:
    from utils.proxy_manager import proxy_manager

    # Get a proxy dict for aiohttp
    proxy_dict = proxy_manager.get_proxy()
    # e.g. {"http": "http://user:pass@host:port", "https": "http://user:pass@host:port"}

    # Create an aiohttp session with proxy
    session = proxy_manager.create_session()
"""

import asyncio
import random
import time
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

from utils.logger import logger


# ── Data Classes ──────────────────────────────────────────────────────────────────

class RotationMode(str, Enum):
    SEQUENTIAL = "sequential"
    RANDOM = "random"
    FAILOVER = "failover"


class ProxyType(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


@dataclass
class ProxyEntry:
    """Represents a single proxy in the pool."""
    id: int
    url: str                     # Full proxy URL, e.g. "http://user:pass@host:port"
    proxy_type: ProxyType = ProxyType.HTTP
    label: str = ""              # Optional friendly label
    enabled: bool = True
    success_count: int = 0
    fail_count: int = 0
    avg_response_time: float = 0.0   # Seconds
    last_tested: Optional[float] = None  # Unix timestamp
    last_used: Optional[float] = None
    added_at: float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        """Calculate success rate (0.0 - 1.0)."""
        total = self.success_count + self.fail_count
        if total == 0:
            return 1.0  # No data — assume good
        return self.success_count / total

    @property
    def is_healthy(self) -> bool:
        """Check if proxy is considered healthy."""
        if not self.enabled:
            return False
        return self.success_rate >= 0.3  # At least 30% success rate


# ── Main Proxy Manager ──────────────────────────────────────────────────────────

class ProxyManager:
    """
    Central proxy pool manager with rotation, health tracking, and validation.

    Proxies can be loaded from:
      1. Environment variable PROXY_URL (single proxy)
      2. Environment variable PROXY_LIST (comma-separated proxies)
      3. Database (persistent storage)
      4. Runtime via /proxy add command
    """

    def __init__(self):
        self._pool: List[ProxyEntry] = []
        self._rotation_mode: RotationMode = RotationMode.SEQUENTIAL
        self._current_index: int = 0
        self._enabled: bool = False
        self._test_url: str = "https://httpbin.org/ip"
        self._test_timeout: int = 10
        self._test_concurrent_limit: int = 5
        self._next_id: int = 1
        self._lock = asyncio.Lock()

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        """Whether proxy routing is globally enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value
        logger.info("Proxy routing %s", "ENABLED" if value else "DISABLED")

    @property
    def rotation_mode(self) -> RotationMode:
        return self._rotation_mode

    @rotation_mode.setter
    def rotation_mode(self, value: RotationMode) -> None:
        self._rotation_mode = RotationMode(value)
        logger.info("Proxy rotation mode set to: %s", self._rotation_mode.value)

    @property
    def pool_size(self) -> int:
        return len(self._pool)

    @property
    def pool(self) -> List[ProxyEntry]:
        return list(self._pool)

    @property
    def healthy_proxies(self) -> List[ProxyEntry]:
        """Return proxies that are enabled and healthy."""
        return [p for p in self._pool if p.is_healthy]

    # ── Proxy URL Parsing ──────────────────────────────────────────────────

    @staticmethod
    def _detect_proxy_type(url: str) -> ProxyType:
        """Detect proxy type from URL scheme."""
        parsed = urlparse(url)
        scheme = parsed.scheme.lower().replace("socks4a", "socks4").replace("socks5h", "socks5")
        try:
            return ProxyType(scheme)
        except ValueError:
            return ProxyType.HTTP  # Default

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize a proxy URL."""
        url = url.strip()
        # Add scheme if missing
        if not url.startswith(("http://", "https://", "socks4://", "socks5://")):
            url = f"http://{url}"
        return url

    @staticmethod
    def _mask_credentials(url: str) -> str:
        """Mask password in proxy URL for display."""
        parsed = urlparse(url)
        if parsed.password:
            host = parsed.hostname or ""
            port = f":{parsed.port}" if parsed.port else ""
            user = parsed.username or ""
            return f"{parsed.scheme}://{user}:****@{host}{port}"
        return url

    # ── Pool Management ────────────────────────────────────────────────────

    def add_proxy(self, url: str, label: str = "") -> ProxyEntry:
        """
        Add a proxy to the pool.

        Args:
            url: Proxy URL (e.g. "http://user:pass@host:port" or "socks5://host:port")
            label: Optional friendly label

        Returns:
            The created ProxyEntry.
        """
        url = self._normalize_url(url)
        proxy_type = self._detect_proxy_type(url)

        entry = ProxyEntry(
            id=self._next_id,
            url=url,
            proxy_type=proxy_type,
            label=label,
        )
        self._next_id += 1
        self._pool.append(entry)

        logger.info("Added proxy #%d: %s (%s)", entry.id, self._mask_credentials(url), proxy_type.value)
        return entry

    def remove_proxy(self, proxy_id: int) -> bool:
        """Remove a proxy by ID. Returns True if found and removed."""
        for i, p in enumerate(self._pool):
            if p.id == proxy_id:
                removed = self._pool.pop(i)
                logger.info("Removed proxy #%d: %s", removed.id, self._mask_credentials(removed.url))
                return True
        return False

    def get_proxy(self, proxy_id: int) -> Optional[ProxyEntry]:
        """Get a specific proxy by ID."""
        for p in self._pool:
            if p.id == proxy_id:
                return p
        return None

    def clear_pool(self) -> int:
        """Clear all proxies. Returns count of removed proxies."""
        count = len(self._pool)
        self._pool.clear()
        self._current_index = 0
        logger.info("Cleared proxy pool (%d proxies removed)", count)
        return count

    def enable_proxy(self, proxy_id: int) -> bool:
        """Enable a specific proxy."""
        proxy = self.get_proxy(proxy_id)
        if proxy:
            proxy.enabled = True
            return True
        return False

    def disable_proxy(self, proxy_id: int) -> bool:
        """Disable a specific proxy."""
        proxy = self.get_proxy(proxy_id)
        if proxy:
            proxy.enabled = False
            return True
        return False

    # ── Proxy Selection (Rotation) ─────────────────────────────────────────

    def _select_proxy(self) -> Optional[ProxyEntry]:
        """
        Select a proxy based on the current rotation mode.

        Returns:
            ProxyEntry or None if pool is empty or all proxies disabled.
        """
        healthy = self.healthy_proxies
        if not healthy:
            return None

        if self._rotation_mode == RotationMode.SEQUENTIAL:
            # Round-robin through healthy proxies
            # Find the next healthy proxy starting from current index
            for _ in range(len(self._pool)):
                candidate = self._pool[self._current_index % len(self._pool)]
                self._current_index = (self._current_index + 1) % len(self._pool)
                if candidate.is_healthy:
                    return candidate
            # Fallback to first healthy
            return healthy[0]

        elif self._rotation_mode == RotationMode.RANDOM:
            return random.choice(healthy)

        elif self._rotation_mode == RotationMode.FAILOVER:
            # Sort by success rate descending, pick the best
            healthy.sort(key=lambda p: (p.success_rate, -p.avg_response_time), reverse=True)
            return healthy[0]

        return healthy[0] if healthy else None

    def get_proxy_url(self) -> Optional[str]:
        """
        Get a proxy URL for use with aiohttp.

        Returns:
            Proxy URL string or None if proxy is disabled or pool is empty.
        """
        if not self._enabled or not self._pool:
            return None

        proxy = self._select_proxy()
        if proxy:
            proxy.last_used = time.time()
            return proxy.url

        return None

    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """
        Get proxy as a dict suitable for aiohttp/requests.

        Returns:
            {"http": "...", "https": "..."} or None.
        """
        url = self.get_proxy_url()
        if url:
            return {"http": url, "https": url}
        return None

    # ── Session Creation ───────────────────────────────────────────────────

    def create_connector(self) -> Optional[aiohttp.BaseConnector]:
        """
        Create an aiohttp connector with proxy support.

        For SOCKS proxies, uses aiohttp_socks if available.
        Falls back to plain TCPConnector for HTTP proxies (uses session proxy param).

        Returns:
            A connector or None (no proxy).
        """
        proxy_url = self.get_proxy_url()
        if not proxy_url:
            return None

        proxy_type = self._detect_proxy_type(proxy_url)

        if proxy_type in (ProxyType.SOCKS4, ProxyType.SOCKS5):
            try:
                from aiohttp_socks import ProxyConnector, ProxyType as SocksType

                socks_type = (
                    SocksType.SOCKS4 if proxy_type == ProxyType.SOCKS4 else SocksType.SOCKS5
                )
                # Parse URL for host/port/user/pass
                parsed = urlparse(proxy_url)
                connector = ProxyConnector(
                    proxy_type=socks_type,
                    host=parsed.hostname or "",
                    port=parsed.port or 1080,
                    username=parsed.username,
                    password=parsed.password,
                    rdns=True,
                )
                logger.debug("Created SOCKS connector for %s", self._mask_credentials(proxy_url))
                return connector
            except ImportError:
                logger.warning(
                    "aiohttp-socks not installed. SOCKS proxy support unavailable. "
                    "Install with: pip install aiohttp-socks"
                )
                # Fall back to plain connector, proxy won't work for SOCKS
                return aiohttp.TCPConnector(limit=10)
            except Exception as exc:
                logger.error("Failed to create SOCKS connector: %s", exc)
                return aiohttp.TCPConnector(limit=10)
        else:
            # HTTP/HTTPS proxy — use plain connector (proxy set on session)
            return aiohttp.TCPConnector(limit=10)

    def create_session(self, timeout: int = 15) -> aiohttp.ClientSession:
        """
        Create an aiohttp ClientSession with proxy configured.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            Configured aiohttp ClientSession.
        """
        proxy_url = self.get_proxy_url()
        proxy_type = self._detect_proxy_type(proxy_url) if proxy_url else ProxyType.HTTP

        if proxy_type in (ProxyType.SOCKS4, ProxyType.SOCKS5):
            # SOCKS uses connector-based proxying
            connector = self.create_connector()
            session = aiohttp.ClientSession(
                connector=connector or aiohttp.TCPConnector(limit=10),
                timeout=aiohttp.ClientTimeout(total=timeout),
            )
        elif proxy_url:
            # HTTP proxy
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
            )
            # Store proxy URL for use with session requests
            session._osint_proxy_url = proxy_url
        else:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
            )

        logger.debug("Created session %s (proxy: %s)", id(session), proxy_url or "none")
        return session

    async def request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        params: dict = None,
        json: dict = None,
        timeout: int = 15,
        **kwargs,
    ) -> dict:
        """
        Convenience method: make an HTTP request through the proxy (if enabled).

        Returns:
            {"ok": True, "status": 200, "data": ...} on success
            {"ok": False, "error": "..."} on failure
        """
        proxy_url = self.get_proxy_url()
        proxy_type = self._detect_proxy_type(proxy_url) if proxy_url else ProxyType.HTTP

        try:
            if proxy_type in (ProxyType.SOCKS4, ProxyType.SOCKS5):
                connector = self.create_connector()
                async with aiohttp.ClientSession(
                    connector=connector or aiohttp.TCPConnector(limit=10),
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as session:
                    async with session.request(
                        method, url, headers=headers,
                        params=params, json=json, **kwargs,
                    ) as resp:
                        if resp.content_type and "json" in resp.content_type:
                            data = await resp.json()
                        else:
                            data = await resp.text()
                        return {"ok": resp.status == 200, "status": resp.status, "data": data}
            elif proxy_url:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as session:
                    async with session.request(
                        method, url, headers=headers, params=params,
                        json=json, proxy=proxy_url, **kwargs,
                    ) as resp:
                        if resp.content_type and "json" in resp.content_type:
                            data = await resp.json()
                        else:
                            data = await resp.text()
                        return {"ok": resp.status == 200, "status": resp.status, "data": data}
            else:
                # No proxy
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as session:
                    async with session.request(
                        method, url, headers=headers,
                        params=params, json=json, **kwargs,
                    ) as resp:
                        if resp.content_type and "json" in resp.content_type:
                            data = await resp.json()
                        else:
                            data = await resp.text()
                        return {"ok": resp.status == 200, "status": resp.status, "data": data}

        except asyncio.TimeoutError:
            return {"ok": False, "error": f"Timeout after {timeout}s"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ── Proxy Testing / Validation ─────────────────────────────────────────

    async def test_proxy(self, proxy: ProxyEntry) -> dict:
        """
        Test a single proxy by making a request to the test URL.

        Returns:
            {
                "proxy_id": int,
                "url": str,
                "working": bool,
                "response_time": float,
                "ip": str,
                "error": str (if failed)
            }
        """
        proxy_type = proxy.proxy_type

        result = {
            "proxy_id": proxy.id,
            "url": self._mask_credentials(proxy.url),
            "type": proxy_type.value,
            "working": False,
            "response_time": 0.0,
            "ip": "",
            "error": "",
        }

        start_time = time.time()

        try:
            if proxy_type in (ProxyType.SOCKS4, ProxyType.SOCKS5):
                try:
                    from aiohttp_socks import ProxyConnector, ProxyType as SocksType
                except ImportError:
                    result["error"] = "aiohttp-socks not installed"
                    proxy.fail_count += 1
                    proxy.last_tested = time.time()
                    return result

                socks_type = (
                    SocksType.SOCKS4 if proxy_type == ProxyType.SOCKS4 else SocksType.SOCKS5
                )
                parsed = urlparse(proxy.url)
                connector = ProxyConnector(
                    proxy_type=socks_type,
                    host=parsed.hostname or "",
                    port=parsed.port or 1080,
                    username=parsed.username,
                    password=parsed.password,
                    rdns=True,
                )
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=self._test_timeout),
                ) as session:
                    async with session.get(self._test_url) as resp:
                        elapsed = time.time() - start_time
                        if resp.status == 200:
                            data = await resp.json()
                            result["working"] = True
                            result["response_time"] = round(elapsed, 3)
                            result["ip"] = data.get("origin", "")
                            proxy.success_count += 1
                        else:
                            result["error"] = f"HTTP {resp.status}"
                            proxy.fail_count += 1
            else:
                # HTTP/HTTPS proxy
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self._test_timeout),
                ) as session:
                    async with session.get(
                        self._test_url, proxy=proxy.url
                    ) as resp:
                        elapsed = time.time() - start_time
                        if resp.status == 200:
                            data = await resp.json()
                            result["working"] = True
                            result["response_time"] = round(elapsed, 3)
                            result["ip"] = data.get("origin", "")
                            proxy.success_count += 1
                        else:
                            result["error"] = f"HTTP {resp.status}"
                            proxy.fail_count += 1

        except asyncio.TimeoutError:
            elapsed = time.time() - start_time
            result["response_time"] = round(elapsed, 3)
            result["error"] = f"Timeout after {self._test_timeout}s"
            proxy.fail_count += 1
        except Exception as exc:
            elapsed = time.time() - start_time
            result["response_time"] = round(elapsed, 3)
            result["error"] = str(exc)[:100]
            proxy.fail_count += 1
        finally:
            # Update proxy stats
            proxy.last_tested = time.time()
            if proxy.success_count + proxy.fail_count > 0:
                total_requests = proxy.success_count + proxy.fail_count
                proxy.avg_response_time = result["response_time"]

        return result

    async def test_all(self, max_concurrent: int = 5) -> List[dict]:
        """
        Test all enabled proxies in the pool concurrently.

        Args:
            max_concurrent: Max number of concurrent tests.

        Returns:
            List of test results.
        """
        enabled_proxies = [p for p in self._pool if p.enabled]
        if not enabled_proxies:
            return []

        semaphore = asyncio.Semaphore(max_concurrent)

        async def _test_with_semaphore(proxy: ProxyEntry) -> dict:
            async with semaphore:
                return await self.test_proxy(proxy)

        tasks = [_test_with_semaphore(p) for p in enabled_proxies]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter exceptions
        clean_results = []
        for r in results:
            if isinstance(r, Exception):
                clean_results.append({"error": str(r)})
            else:
                clean_results.append(r)

        return clean_results

    # ── Initialization ─────────────────────────────────────────────────────

    def load_from_env(self) -> None:
        """
        Load proxy configuration from environment variables.

        Checks:
          - PROXY_URL: Single proxy URL
          - PROXY_LIST: Comma-separated proxy URLs
          - PROXY_ENABLED: "true"/"1" to auto-enable
          - PROXY_ROTATION: "sequential"|"random"|"failover"
        """
        import os

        proxy_url = os.getenv("PROXY_URL", "").strip()
        proxy_list = os.getenv("PROXY_LIST", "").strip()
        proxy_enabled = os.getenv("PROXY_ENABLED", "").strip().lower()
        proxy_rotation = os.getenv("PROXY_ROTATION", "").strip().lower()
        test_url = os.getenv("PROXY_TEST_URL", "").strip()

        if test_url:
            self._test_url = test_url

        if proxy_rotation in RotationMode.__members__:
            self._rotation_mode = RotationMode(proxy_rotation)

        # Load single proxy
        if proxy_url:
            self.add_proxy(proxy_url, label="env:PROXY_URL")
            logger.info("Loaded proxy from PROXY_URL env var")

        # Load proxy list
        if proxy_list:
            for i, url in enumerate(proxy_list.split(",")):
                url = url.strip()
                if url:
                    self.add_proxy(url, label=f"env:PROXY_LIST[{i}]")
            logger.info("Loaded %d proxies from PROXY_LIST env var", len(proxy_list.split(",")))

        # Auto-enable if requested
        if proxy_enabled in ("true", "1", "yes"):
            self._enabled = True
            logger.info("Proxy auto-enabled via PROXY_ENABLED env var")

    # ── Statistics ─────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Get proxy pool statistics."""
        total = len(self._pool)
        enabled = len([p for p in self._pool if p.enabled])
        healthy = len(self.healthy_proxies)
        by_type = {}
        for ptype in ProxyType:
            by_type[ptype.value] = len([p for p in self._pool if p.proxy_type == ptype])

        tested = [p for p in self._pool if p.last_tested is not None]
        avg_success_rate = (
            sum(p.success_rate for p in tested) / len(tested) * 100
            if tested else 0
        )
        avg_response = (
            sum(p.avg_response_time for p in tested) / len(tested)
            if tested else 0
        )

        return {
            "enabled": self._enabled,
            "rotation_mode": self._rotation_mode.value,
            "total_proxies": total,
            "enabled_proxies": enabled,
            "healthy_proxies": healthy,
            "by_type": by_type,
            "avg_success_rate": round(avg_success_rate, 1),
            "avg_response_time": round(avg_response, 3),
            "tested_count": len(tested),
        }


# ── Singleton ────────────────────────────────────────────────────────────────────

proxy_manager = ProxyManager()

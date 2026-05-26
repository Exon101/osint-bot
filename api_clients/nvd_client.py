"""
NVD (National Vulnerability Database) API Client
"""

import aiohttp
from utils.proxy_manager import proxy_manager


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key=None):
        self.api_key = api_key
        self.headers = {}
        if api_key:
            self.headers["apiKey"] = api_key

    async def _request(self, url: str, timeout: int = 30) -> dict | None:
        """Internal proxied request helper."""
        proxy_url = proxy_manager.get_proxy_url()
        proxy_type = proxy_manager._detect_proxy_type(proxy_url) if proxy_url else None

        try:
            if proxy_url and proxy_type and proxy_type.value in ("socks4", "socks5"):
                connector = proxy_manager.create_connector()
                async with aiohttp.ClientSession(
                    connector=connector or aiohttp.TCPConnector(limit=10),
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as session:
                    async with session.get(url, headers=self.headers) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return None
            elif proxy_url:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as session:
                    async with session.get(url, headers=self.headers, proxy=proxy_url) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return None
            else:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=self.headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return None
        except Exception:
            return None

    async def get_cve(self, cve_id: str) -> dict | None:
        url = f"{self.BASE_URL}?cveId={cve_id}"
        data = await self._request(url)
        if data:
            vulns = data.get("vulnerabilities", [])
            return vulns[0] if vulns else None
        return None

    async def search(self, keyword: str, results: int = 5) -> list:
        url = f"{self.BASE_URL}?keywordSearch={keyword}&resultsPerPage={results}"
        data = await self._request(url)
        if data:
            return data.get("vulnerabilities", [])
        return []

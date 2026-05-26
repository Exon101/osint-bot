"""
VirusTotal API Client — https://www.virustotal.com
"""

import aiohttp
from config import config
from utils.proxy_manager import proxy_manager


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key=None):
        self.api_key = api_key or config.VIRUSTOTAL_API_KEY
        self.headers = {}
        if self.api_key:
            self.headers["x-apikey"] = self.api_key

    async def _request(self, url: str, timeout: int = 20) -> dict:
        """Internal method: make a proxied request to VirusTotal."""
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
                        if resp.status == 404:
                            return {"error": "Not found in VirusTotal"}
                        return {"error": f"VirusTotal HTTP {resp.status}"}
            elif proxy_url:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as session:
                    async with session.get(url, headers=self.headers, proxy=proxy_url) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        if resp.status == 404:
                            return {"error": "Not found in VirusTotal"}
                        return {"error": f"VirusTotal HTTP {resp.status}"}
            else:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=self.headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        if resp.status == 404:
                            return {"error": "Not found in VirusTotal"}
                        return {"error": f"VirusTotal HTTP {resp.status}"}
        except Exception as exc:
            return {"error": str(exc)}

    async def lookup_file(self, file_hash: str) -> dict:
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        url = f"{self.BASE_URL}/files/{file_hash}"
        return await self._request(url)

    async def lookup_url(self, url: str) -> dict:
        import base64
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"{self.BASE_URL}/urls/{url_id}"
        return await self._request(api_url)

    async def lookup_domain(self, domain: str) -> dict:
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        url = f"{self.BASE_URL}/domains/{domain}"
        return await self._request(url)

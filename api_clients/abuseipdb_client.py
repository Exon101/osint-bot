"""
AbuseIPDB Client — https://www.abuseipdb.com
"""

import aiohttp
from config import config
from utils.proxy_manager import proxy_manager


class AbuseIPDBClient:
    CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key=None):
        self.api_key = api_key or config.ABUSEIPDB_API_KEY

    async def check(self, ip: str, max_age_days: int = 30) -> dict:
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max_age_days,
            "verbose": True,
        }
        headers = {"Key": self.api_key, "Accept": "application/json"}

        proxy_url = proxy_manager.get_proxy_url()
        proxy_type = proxy_manager._detect_proxy_type(proxy_url) if proxy_url else None

        try:
            if proxy_url and proxy_type and proxy_type.value in ("socks4", "socks5"):
                connector = proxy_manager.create_connector()
                async with aiohttp.ClientSession(
                    connector=connector or aiohttp.TCPConnector(limit=10),
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as session:
                    async with session.get(self.CHECK_URL, headers=headers, params=params) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"AbuseIPDB HTTP {resp.status}"}
            elif proxy_url:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as session:
                    async with session.get(
                        self.CHECK_URL, headers=headers, params=params, proxy=proxy_url
                    ) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"AbuseIPDB HTTP {resp.status}"}
            else:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        self.CHECK_URL, headers=headers, params=params,
                        timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"AbuseIPDB HTTP {resp.status}"}
        except Exception as exc:
            return {"error": str(exc)}

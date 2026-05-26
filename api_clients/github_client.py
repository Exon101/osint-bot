"""
GitHub API Client
"""

import aiohttp
from config import config
from utils.proxy_manager import proxy_manager


class GitHubClient:
    BASE_URL = "https://api.github.com"

    def __init__(self, token=None):
        self.token = token or getattr(config, "GITHUB_TOKEN", None)
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "OSINT-Bot-Educational/2.0",
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"

    async def _request(self, url: str, timeout: int = 15) -> dict:
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
                        return {"error": f"GitHub HTTP {resp.status}"}
            elif proxy_url:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as session:
                    async with session.get(url, headers=self.headers, proxy=proxy_url) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"GitHub HTTP {resp.status}"}
            else:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=self.headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        return {"error": f"GitHub HTTP {resp.status}"}
        except Exception as exc:
            return {"error": str(exc)}

    async def get_repo(self, owner: str, repo: str) -> dict:
        url = f"{self.BASE_URL}/repos/{owner}/{repo}"
        return await self._request(url)

    async def list_releases(self, owner: str, repo: str, per_page: int = 5) -> list:
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/releases?per_page={per_page}"
        result = await self._request(url)
        return result if isinstance(result, list) else []

    async def search_repos(self, query: str, per_page: int = 5) -> dict:
        url = f"{self.BASE_URL}/search/repositories?q={query}&per_page={per_page}&sort=stars"
        return await self._request(url)

    async def get_readme(self, owner: str, repo: str) -> dict:
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/readme"
        return await self._request(url)

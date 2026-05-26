"""
Nuclei Scanner API Client
Interacts with ProjectDiscovery Cloud API (PDCP) for remote Nuclei template scanning.

Supports:
    - Template listing and search
    - Target scanning via cloud API
    - Scan result retrieval and history

API Docs: https://docs.projectdiscovery.io/cloud/api-reference
"""

import aiohttp
from typing import Optional, List, Dict, Any
from utils.proxy_manager import proxy_manager
from utils.logger import logger


class NucleiClient:
    """Client for ProjectDiscovery Nuclei Cloud API."""

    BASE_URL = "https://cloud.projectdiscovery.io/api/v1"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            self.headers["X-API-Key"] = self.api_key

    def _is_configured(self) -> bool:
        """Check if the Nuclei API key is set."""
        return bool(self.api_key)

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """Make an API request with proxy support."""
        url = f"{self.BASE_URL}{path}"
        proxy_url = proxy_manager.get_proxy_url()

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as session:
                kwargs = {
                    "method": method,
                    "url": url,
                    "headers": self.headers,
                }
                if params:
                    kwargs["params"] = params
                if json_data:
                    kwargs["json"] = json_data
                if proxy_url:
                    proxy_type = proxy_manager._detect_proxy_type(proxy_url)
                    if proxy_type and proxy_type.value in ("socks4", "socks5"):
                        connector = proxy_manager.create_connector()
                        kwargs["connector"] = connector or aiohttp.TCPConnector(limit=10)
                    else:
                        kwargs["proxy"] = proxy_url

                async with session.request(**kwargs) as resp:
                    body = await resp.text()

                    if resp.status == 401:
                        return {"error": "Invalid or expired Nuclei API key"}
                    if resp.status == 403:
                        return {"error": "Access denied. Check your API key permissions."}
                    if resp.status == 429:
                        return {"error": "Nuclei API rate limit reached. Please wait."}
                    if resp.status >= 500:
                        return {"error": f"Nuclei API server error (HTTP {resp.status})"}

                    try:
                        data = await resp.json(content_type=None)
                    except Exception:
                        data = {"raw": body[:2000]}

                    if resp.status >= 400:
                        return {"error": data.get("error", data.get("message", f"HTTP {resp.status}"))}

                    return {"ok": True, "status": resp.status, "data": data}

        except aiohttp.ClientError as exc:
            logger.error("Nuclei API request failed: %s", exc)
            return {"error": f"Network error: {exc}"}
        except Exception as exc:
            logger.error("Nuclei API unexpected error: %s", exc)
            return {"error": str(exc)}

    # ── Template Management ────────────────────────────────────────────

    async def list_templates(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """List available Nuclei templates."""
        params = {"limit": limit}
        if category:
            params["category"] = category
        if severity:
            params["severity"] = severity
        return await self._request("GET", "/templates", params=params)

    async def search_templates(self, query: str, limit: int = 20) -> Dict[str, Any]:
        """Search templates by keyword (e.g., 'xss', 'sql-injection', 'wordpress')."""
        return await self._request(
            "GET", "/templates/search", params={"q": query, "limit": limit}
        )

    async def get_template_info(self, template_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific template."""
        return await self._request("GET", f"/templates/{template_id}")

    # ── Scan Operations ───────────────────────────────────────────────

    async def start_scan(
        self,
        target: str,
        templates: Optional[List[str]] = None,
        severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Start a Nuclei scan against a target URL or domain.

        Args:
            target: The target URL (e.g., 'https://example.com') or domain.
            templates: Optional list of specific template IDs to run.
            severity: Filter by severity ('critical', 'high', 'medium', 'low', 'info').
            tags: Optional list of template tags to include.

        Returns:
            Scan creation response with scan_id.
        """
        payload: Dict[str, Any] = {"target": target}

        if templates:
            payload["templates"] = templates
        if severity:
            payload["severity"] = severity
        if tags:
            payload["tags"] = tags

        return await self._request("POST", "/scans", json_data=payload)

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get the status and progress of a scan."""
        return await self._request("GET", f"/scans/{scan_id}")

    async def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Get the findings/results of a completed scan."""
        return await self._request("GET", f"/scans/{scan_id}/results")

    async def list_scans(self, limit: int = 10) -> Dict[str, Any]:
        """List recent scans."""
        return await self._request("GET", "/scans", params={"limit": limit})

    async def cancel_scan(self, scan_id: str) -> Dict[str, Any]:
        """Cancel a running scan."""
        return await self._request("DELETE", f"/scans/{scan_id}")

    # ── Quick Scan (single-request flow) ──────────────────────────────

    async def quick_scan(self, target: str) -> Dict[str, Any]:
        """
        Perform a quick scan using default templates.
        Returns findings immediately (long-poll up to 120s).
        """
        result = await self.start_scan(target)
        if not result.get("ok"):
            return result

        scan_id = result.get("data", {}).get("scan_id") or result.get("data", {}).get("id")
        if not scan_id:
            return {"error": "Scan started but no scan ID returned"}

        # Poll for results (max 120 seconds)
        import asyncio
        for _ in range(24):
            await asyncio.sleep(5)
            status = await self.get_scan_status(scan_id)
            if not status.get("ok"):
                continue

            scan_data = status.get("data", {})
            state = scan_data.get("status", "")

            if state in ("completed", "done", "finished"):
                results = await self.get_scan_results(scan_id)
                return results if results.get("ok") else {"error": "Scan completed but could not retrieve results"}
            elif state in ("failed", "error", "cancelled"):
                return {"error": f"Scan {state}: {scan_data.get('error', 'Unknown reason')}"}

        return {"error": "Scan timed out (120s). Use /nuclei status <id> to check later."}

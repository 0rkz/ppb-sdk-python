"""Mercat — Publisher marketplace search and discovery."""

import aiohttp
from typing import Optional


class Mercat:
    def __init__(self, indexer_url: str):
        self.indexer_url = indexer_url.rstrip("/")

    async def search(self, topic: str = None,
                     max_price: int = None, sort_by: str = "subscribers",
                     limit: int = 20, offset: int = 0) -> list[dict]:
        """Search for publishers on the marketplace."""
        params = {"sort": sort_by, "limit": str(limit), "offset": str(offset)}
        if topic: params["topic"] = topic
        if max_price: params["maxPrice"] = str(max_price)

        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.indexer_url}/publishers", params=params) as resp:
                resp.raise_for_status()
                return await resp.json()

    async def get_publisher(self, address: str) -> dict:
        """Get full publisher profile."""
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.indexer_url}/publisher/{address}") as resp:
                resp.raise_for_status()
                return await resp.json()

    async def get_top(self, topic: str, limit: int = 10) -> list[dict]:
        """Get top publishers by topic."""
        return await self.search(topic=topic, sort_by="subscribers", limit=limit)

    async def health(self) -> dict:
        """Check indexer health."""
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.indexer_url}/health") as resp:
                resp.raise_for_status()
                return await resp.json()

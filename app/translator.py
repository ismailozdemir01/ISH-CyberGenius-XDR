from __future__ import annotations

import uuid
from typing import Any

import httpx


class TranslatorClient:
    def __init__(self, endpoint: str, key: str, region: str | None, timeout: float = 30.0):
        self.endpoint = endpoint.rstrip("/")
        self.key = key
        self.region = region
        self.timeout = timeout

    async def _request(self, path: str, *, params: list[tuple[str, str]], body: Any) -> Any:
        headers = {
            "Ocp-Apim-Subscription-Key": self.key,
            "Content-Type": "application/json",
            "X-ClientTraceId": str(uuid.uuid4()),
        }
        if self.region:
            headers["Ocp-Apim-Subscription-Region"] = self.region
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(f"{self.endpoint}{path}", params=params, headers=headers, json=body)
            response.raise_for_status()
            return response.json()

    async def detect(self, text: str) -> dict[str, Any]:
        data = await self._request("/detect", params=[("api-version", "3.0")], body=[{"text": text}])
        item = data[0] if data else {}
        return {
            "language": item.get("language"),
            "score": item.get("score"),
            "alternatives": item.get("alternatives", []),
        }

    async def translate(self, text: str, target_language: str, source_language: str | None = None) -> dict[str, Any]:
        params = [("api-version", "3.0"), ("to", target_language)]
        if source_language:
            params.append(("from", source_language))
        data = await self._request("/translate", params=params, body=[{"text": text}])
        item = data[0] if data else {}
        translation = (item.get("translations") or [{}])[0]
        return {
            "text": translation.get("text", ""),
            "language": translation.get("to"),
            "detected_language": item.get("detectedLanguage"),
        }

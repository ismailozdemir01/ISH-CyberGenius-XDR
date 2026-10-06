from __future__ import annotations

from typing import Any
import httpx


class GumroadError(RuntimeError):
    pass


def gumroad_sale_fields(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "license_key": str(payload.get("license_key") or "").strip(),
        "product_permalink": str(payload.get("product_permalink") or payload.get("product_id") or "").strip(),
        "email": str(payload.get("email") or "").strip().lower(),
        "order_number": str(payload.get("order_number") or "").strip(),
        "full_name": str(payload.get("full_name") or "").strip(),
        "price": str(payload.get("price") or "").strip(),
        "currency": str(payload.get("currency") or "").strip(),
        "variants": str(payload.get("variants") or "").strip(),
        "quantity": str(payload.get("quantity") or "1").strip(),
    }


class GumroadClient:
    def __init__(self, base_url: str, product_permalink: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.product_permalink = product_permalink
        self.timeout = timeout

    async def verify(self, license_key: str, increment_uses_count: bool = False) -> dict[str, Any]:
        if not self.product_permalink:
            raise GumroadError("GUMROAD_PRODUCT_PERMALINK is not configured.")
        if not license_key.strip():
            raise GumroadError("license_key is required.")
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/v2/licenses/verify",
                data={
                    "product_permalink": self.product_permalink,
                    "license_key": license_key.strip(),
                    "increment_uses_count": "true" if increment_uses_count else "false",
                },
            )
        if response.status_code >= 400:
            raise GumroadError(f"Gumroad license verification failed with HTTP {response.status_code}.")
        return response.json()

from typing import Any
import httpx

class DefenderClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, base_url: str, timeout: float = 30.0):
        self.tenant_id=tenant_id
        self.client_id=client_id
        self.client_secret=client_secret
        self.base_url=base_url.rstrip("/")
        self.timeout=timeout

    async def _token(self) -> str:
        url=f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data={
            "client_id":self.client_id,
            "client_secret":self.client_secret,
            "scope":"https://graph.microsoft.com/.default",
            "grant_type":"client_credentials",
        }
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r=await c.post(url,data=data)
            r.raise_for_status()
            return r.json()["access_token"]

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        token=await self._token()
        headers=kwargs.pop("headers", {})
        headers["Authorization"]=f"Bearer {token}"
        headers["Accept"]="application/json"
        async with httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout) as c:
            r=await c.request(method,path,headers=headers,**kwargs)
            r.raise_for_status()
            return r.json()

    async def incidents(self, top: int = 100) -> dict[str, Any]:
        return await self._request("GET", "/security/incidents", params={"$top": min(max(top,1),100)})

    async def hunting_query(self, query: str, timespan: str | None = None) -> dict[str, Any]:
        body={"Query":query}
        if timespan:
            body["Timespan"]=timespan
        return await self._request("POST", "/security/runHuntingQuery", json=body)

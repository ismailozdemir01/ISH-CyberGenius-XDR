from typing import Any
import httpx

class DefenderClient:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        graph_base_url: str,
        timeout: float = 30.0,
        defender_api_base_url: str = "https://api.security.microsoft.com",
    ):
        self.tenant_id=tenant_id
        self.client_id=client_id
        self.client_secret=client_secret
        self.graph_base_url=graph_base_url.rstrip("/")
        self.defender_api_base_url=defender_api_base_url.rstrip("/")
        self.timeout=timeout

    async def _token(self, scope: str) -> str:
        url=f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data={
            "client_id":self.client_id,
            "client_secret":self.client_secret,
            "scope":scope,
            "grant_type":"client_credentials",
        }
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r=await c.post(url,data=data)
            r.raise_for_status()
            return r.json()["access_token"]

    async def _request(self, method: str, path: str, scope: str, base_url: str, **kwargs: Any) -> dict[str, Any]:
        token=await self._token(scope)
        headers=kwargs.pop("headers", {})
        headers["Authorization"]=f"Bearer {token}"
        headers["Accept"]="application/json"
        async with httpx.AsyncClient(base_url=base_url, timeout=self.timeout) as c:
            r=await c.request(method,path,headers=headers,**kwargs)
            r.raise_for_status()
            if not r.content:
                return {}
            return r.json()

    async def _graph(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return await self._request(
            method, path, "https://graph.microsoft.com/.default", self.graph_base_url, **kwargs
        )

    async def _defender(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return await self._request(
            method, path, "https://api.securitycenter.microsoft.com/.default", self.defender_api_base_url, **kwargs
        )

    async def incidents(self, top: int = 100) -> dict[str, Any]:
        return await self._graph("GET", "/security/incidents", params={"$top": min(max(top,1),100)})

    async def incident(self, incident_id: str) -> dict[str, Any]:
        return await self._graph("GET", f"/security/incidents/{incident_id}")

    async def update_incident(self, incident_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        return await self._graph("PATCH", f"/security/incidents/{incident_id}", json=changes)

    async def incident_comment(self, incident_id: str, comment: str) -> dict[str, Any]:
        return await self._graph(
            "POST",
            f"/security/incidents/{incident_id}/comments",
            json={"@odata.type":"microsoft.graph.security.alertComment","comment":comment},
        )

    async def hunting_query(self, query: str, timespan: str | None = None) -> dict[str, Any]:
        body={"Query":query}
        if timespan:
            body["Timespan"]=timespan
        return await self._graph("POST", "/security/runHuntingQuery", json=body)

    async def machines(self, top: int = 100) -> dict[str, Any]:
        return await self._defender("GET", "/api/machines", params={"$top": min(max(top,1),10000)})

    async def isolate_machine(self, machine_id: str, comment: str, isolation_type: str = "Full") -> dict[str, Any]:
        if isolation_type not in {"Full", "Selective", "UnManagedDevice"}:
            raise ValueError("isolation_type must be Full, Selective, or UnManagedDevice")
        return await self._defender(
            "POST",
            f"/api/machines/{machine_id}/isolate",
            json={"Comment":comment,"IsolationType":isolation_type},
        )

    async def unisolate_machine(self, machine_id: str, comment: str) -> dict[str, Any]:
        return await self._defender(
            "POST",
            f"/api/machines/{machine_id}/unisolate",
            json={"Comment":comment},
        )

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    app_name: str = "ISH-CyberGenius-XDR"
    database_path: str = "./data/xdr.db"
    graph_base_url: str = "https://graph.microsoft.com/v1.0"
    defender_api_base_url: str = "https://api.security.microsoft.com"
    translator_endpoint: str = "https://api.cognitive.microsofttranslator.com"
    translator_key: str | None = None
    translator_region: str | None = None
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    api_key: str | None = None
    request_timeout: float = 30.0

    @property
    def graph_configured(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    @property
    def translator_configured(self) -> bool:
        return bool(self.translator_key)

settings = Settings()

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    app_name: str = "OZHEX-CyberGenius-XDR"
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
    gumroad_api_base_url: str = "https://api.gumroad.com"
    gumroad_product_permalink: str | None = None
    gumroad_ping_secret: str | None = None
    license_product: str = "OZHEX-CyberGenius-XDR"
    license_public_key: str | None = None
    license_revocation_url: str | None = None
    github_actions_token: str | None = None
    github_license_repo: str = "ismailozdemir01/OZHEX-CyberGenius-XDR"
    github_license_workflow: str = "license-issue.yml"
    github_license_ref: str = "main"
    license_dispatch_enabled: bool = True
    license_dispatch_timeout: float = 15.0
    license_fail_closed_revocation: bool = True
    license_callback_url: str | None = None
    license_callback_secret: str | None = None

    @property
    def graph_configured(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    @property
    def translator_configured(self) -> bool:
        return bool(self.translator_key)


settings = Settings()

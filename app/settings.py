from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./healthbridge.db"
    write_token: str = "change-me-write"
    read_token: str = "change-me-read"
    share_token: str = ""
    share_enabled: bool = False
    max_body_bytes: int = 20_000_000
    app_name: str = "HealthBridge Server"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()

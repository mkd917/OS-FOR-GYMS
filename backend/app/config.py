"""Application configuration, read from the environment (12-factor)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="GYMOPS_")

    # ── Datastores ──────────────────────────────────────────────────
    database_url: str = "postgresql://gymops:gymops@localhost:5432/gymops"
    redis_url: str = "redis://localhost:6379/0"

    # ── Connection pools ────────────────────────────────────────────
    # The app pool serves owner/member portals. The door hot-path uses a
    # separate, isolated pool (ARCHITECTURE.md §1, bottleneck 1) so a slow
    # analytics query can never starve the turnstile.
    app_pool_min: int = 2
    app_pool_max: int = 10
    hw_pool_min: int = 2
    hw_pool_max: int = 8

    # ── Auth / sessions ─────────────────────────────────────────────
    jwt_secret: str = "change-me-in-prod-please"          # HS256 signing key
    jwt_alg: str = "HS256"
    access_token_ttl_seconds: int = 60 * 60 * 8           # 8h working session

    # ── Member QR (must mirror hardware verify-access constants) ─────
    qr_window_seconds: int = 15
    qr_skew_windows: int = 1

    # ── HTTP server / CORS ───────────────────────────────────────────
    # Runs on 8080 to avoid the kiro-gateway already bound to :8000.
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    # Browser origins allowed to call the API. The Astro dev server defaults
    # to :4321; 127.0.0.1 and localhost are distinct origins, so list both.
    cors_allow_origins: list[str] = [
        "http://localhost:4321",
        "http://127.0.0.1:4321",
    ]


@lru_cache
def get_settings() -> Settings:
    return Settings()

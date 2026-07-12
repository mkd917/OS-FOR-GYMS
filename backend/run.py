"""Dev entrypoint: `python run.py` → uvicorn on the configured host/port.

Runs on 8080 (config.api_port) to avoid the kiro-gateway already on :8000.
Equivalent to: uvicorn app.main:app --reload --port 8080
"""
import uvicorn

from app.config import get_settings

if __name__ == "__main__":
    s = get_settings()
    uvicorn.run("app.main:app", host=s.api_host, port=s.api_port, reload=True)

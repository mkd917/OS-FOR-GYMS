"""GymOpsSaaS API entrypoint.

Mounts three routers behind one app:
  • /api/auth/*      — login/signup, returns the portal a user belongs to
  • /api/owner/*     — B2B Owner Portal (owner role only)
  • /api/member/*    — B2C Member Portal (member role only)
  • /api/hardware/*  — ESP32 door verify-access (device-key auth, no JWT)

The owner/member split is enforced by role-gating dependencies in deps.py, not
by convention — see require_owner / require_member.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import db
from .config import get_settings
from .routers import auth, hardware, member, owner


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Refuse to start with the placeholder signing key. With it, anyone can
    # forge a JWT carrying {role:'owner', gym_id:<any>} and reach every
    # tenant's data — the secret is the only thing standing between a request
    # and full cross-tenant access. Set GYMOPS_JWT_SECRET to a long random
    # value in every non-throwaway environment.
    if get_settings().jwt_secret == "change-me-in-prod-please":
        raise RuntimeError(
            "GYMOPS_JWT_SECRET is unset (using the built-in placeholder). "
            "Set it to a long random secret before starting the API."
        )
    await db.connect()
    try:
        yield
    finally:
        await db.disconnect()


app = FastAPI(
    title="GymOpsSaaS API",
    version="0.1.0",
    summary="Multi-tenant gym OS: dual-portal RBAC + IoT door access.",
    lifespan=lifespan,
)

# CORS — let the Astro frontend (different origin/port) call this API from the
# browser. Without this, the login fetch is blocked before it ever reaches us.
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(owner.router)
app.include_router(member.router)
app.include_router(hardware.router)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok"}

"""Request-scoped auth & RBAC dependencies — the dual-portal enforcement point.

The rule "owners see the B2B portal, members see the B2C portal" is enforced
here, structurally:

  • current_principal  — verifies the JWT, returns {gym_id, user_id, role}
  • tenant_db          — yields a Postgres connection already bound to the
                         caller's gym via the RLS GUC (so even a buggy query
                         can't cross tenants)
  • require_owner      — 403 unless role == 'owner'   → gates /api/owner/*
  • require_member     — 403 unless role == 'member'  → gates /api/member/*

A token is the only thing trusted. Role comes from the signed claim, not from
anything the client can set per-request.
"""
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from .db import tenant_conn
from .security import decode_token

_bearer = HTTPBearer(auto_error=False)


class Principal(BaseModel):
    gym_id: str
    user_id: str
    role: str            # 'owner' | 'member'


async def current_principal(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    # Missing/blank Authorization header → 401 (authentication required),
    # not 403 (which HTTPBearer's auto_error would wrongly return).
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not_authenticated")
    try:
        claims = decode_token(creds.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token_expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_token")

    try:
        return Principal(
            gym_id=claims["gym_id"], user_id=claims["sub"], role=claims["role"]
        )
    except KeyError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "malformed_claims")


async def tenant_db(principal: Principal = Depends(current_principal)):
    """A tenant-bound connection for the whole request transaction."""
    async with tenant_conn(principal.gym_id) as conn:
        yield conn


def _require_role(expected: str):
    async def guard(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.role != expected:
            # 403, not 404: the caller is authenticated but on the wrong portal.
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"this endpoint is for role '{expected}', "
                       f"you are '{principal.role}'",
            )
        return principal
    return guard


require_owner = _require_role("owner")     # → Owner Portal (B2B)
require_member = _require_role("member")   # → Member Portal (B2C)

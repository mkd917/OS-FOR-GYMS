"""Password hashing (argon2id) and stateless session tokens (JWT).

The JWT is the spine of the dual-portal model: it carries the tenant (`gym_id`),
the identity (`sub`), and the **role** (`owner` | `member`). Every protected
route reads the role from the verified token — never from a client-supplied
field — so the portal split can't be spoofed by tampering with a request body.
"""
import time
import uuid

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from .config import get_settings

_ph = PasswordHasher()   # argon2id with sane defaults


# ── Passwords ───────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return _ph.hash(plain)


def verify_password(stored_hash: str, plain: str) -> bool:
    try:
        return _ph.verify(stored_hash, plain)
    except (VerificationError, InvalidHashError):
        # Covers both a wrong password (VerifyMismatchError, a VerificationError
        # subclass) and a malformed/corrupted stored hash (InvalidHashError,
        # which is NOT a VerificationError subclass) — either way the
        # credentials don't verify, so return False rather than 500.
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _ph.check_needs_rehash(stored_hash)


# ── Session tokens ──────────────────────────────────────────────────
def issue_token(*, gym_id: str, user_id: str, role: str) -> str:
    s = get_settings()
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "gym_id": str(gym_id),
        "role": role,                       # 'owner' | 'member' — drives routing
        "iat": now,
        "exp": now + s.access_token_ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_alg)


def decode_token(token: str) -> dict:
    """Verify signature + expiry. Raises jwt.PyJWTError on any problem."""
    s = get_settings()
    return jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_alg])

"""Canonical dynamic-QR token codec — the single source of truth shared by the
member app (which *signs*) and the ESP32 door endpoint (which *verifies*).

These two sides MUST agree byte-for-byte. If the member portal and the hardware
verifier each had their own copy of this logic and one drifted, every member
would be denied at the turnstile. So the sign/parse/verify primitives live here,
once, and both routers import them.

Token wire format (matches ARCHITECTURE.md §3 verify-access exactly):

    base64url( "{gym_id}.{member_id}.{ts}.{sig}" )

where
    window = ts // WINDOW_SECONDS
    sig    = HMAC_SHA256(secret, "{gym_id}.{member_id}.{window}").hexdigest()[:16]

Verification accepts the current window ± SKEW_WINDOWS to tolerate clock drift
between the phone and the ESP32's RTC.
"""
import hashlib
import hmac
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode

from .config import get_settings


def _window_for(ts: int) -> int:
    return ts // get_settings().qr_window_seconds


def sign_window(secret: bytes, gym_id: str, member_id: str, window: int) -> str:
    """The 16-hex-char signature for one (member, window). Used by both sides."""
    msg = f"{gym_id}.{member_id}.{window}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()[:16]


def build_token(secret: bytes, gym_id: str, member_id: str, *, now: int | None = None
                ) -> tuple[str, int]:
    """Produce the QR string the member app renders, plus seconds until the
    current window rolls over (when the app should fetch the next code)."""
    s = get_settings()
    ts = int(time.time()) if now is None else now
    window = ts // s.qr_window_seconds
    sig = sign_window(secret, gym_id, member_id, window)
    raw = f"{gym_id}.{member_id}.{ts}.{sig}"
    token = urlsafe_b64encode(raw.encode()).decode()
    seconds_into_window = ts % s.qr_window_seconds
    refresh_in = s.qr_window_seconds - seconds_into_window
    return token, refresh_in


def parse_token(token: str) -> tuple[str, str, int, str] | None:
    """base64url → (gym_id, member_id, ts, sig). None if malformed."""
    try:
        raw = urlsafe_b64decode(token.encode()).decode()
        gym_id, member_id, ts, sig = raw.split(".")
        return gym_id, member_id, int(ts), sig
    except Exception:
        return None


def verify(secret: bytes, gym_id: str, member_id: str, ts: int, sig: str,
           *, now: int | None = None) -> bool:
    """Constant-time check across the accepted window range. Used by the door."""
    s = get_settings()
    current = int(time.time()) if now is None else now
    # Freshness: the timestamp itself must be near now.
    if abs(current - ts) > s.qr_window_seconds * (s.qr_skew_windows + 1):
        return False
    window = ts // s.qr_window_seconds
    for drift in range(-s.qr_skew_windows, s.qr_skew_windows + 1):
        expected = sign_window(secret, gym_id, member_id, window + drift)
        if hmac.compare_digest(expected, sig):
            return True
    return False

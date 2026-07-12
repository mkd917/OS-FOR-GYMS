"""Small helpers to provision tenants/users through the real API.

We go through the HTTP signup endpoints (not raw SQL inserts) so the tests
exercise the same RLS-bound write paths the app uses in production — e.g. a
member signup really does create the member_profiles.qr_secret the door verifies.
"""
from dataclasses import dataclass

from httpx import AsyncClient


@dataclass
class Session:
    token: str
    gym_id: str
    user_id: str
    role: str

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


def _session(data: dict) -> Session:
    return Session(
        token=data["access_token"],
        gym_id=data["gym_id"],
        user_id=data["user_id"],
        role=data["role"],
    )


async def signup_owner(client: AsyncClient, slug: str, *, password: str = "supersecret"
                       ) -> Session:
    res = await client.post("/api/auth/signup/owner", json={
        "gym_slug": slug,
        "gym_name": f"{slug.title()} Fitness",
        "full_name": f"{slug} owner",
        "email": f"owner@{slug}.test",
        "password": password,
    })
    assert res.status_code == 201, res.text
    return _session(res.json())


async def signup_member(client: AsyncClient, slug: str, *, email: str | None = None,
                        password: str = "supersecret") -> Session:
    res = await client.post("/api/auth/signup/member", json={
        "gym_slug": slug,
        "full_name": "Test Member",
        "email": email or f"member@{slug}.test",
        "password": password,
    })
    assert res.status_code == 201, res.text
    return _session(res.json())


async def provision_device(client: AsyncClient, owner: Session, label: str) -> dict:
    """Returns the device payload including the one-time raw `device_key`."""
    res = await client.post("/api/owner/devices", headers=owner.auth,
                            json={"label": label})
    assert res.status_code == 201, res.text
    return res.json()

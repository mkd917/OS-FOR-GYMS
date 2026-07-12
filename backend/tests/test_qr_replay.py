"""QR replay protection on the hardware door path.

The dynamic QR rotates per window, but within a window the same signed token
could be presented twice (photo of the screen, captured request). The door must
grant the first presentation and reject the replay, enforced by the Redis nonce
guard in hardware.verify_access (`SET nonce:{sig} NX`).
"""
from tests.helpers import provision_device, signup_member, signup_owner


async def _member_qr_token(client, member) -> str:
    res = await client.get("/api/member/qr", headers=member.auth)
    assert res.status_code == 200, res.text
    return res.json()["token"]


async def test_qr_replay_is_rejected(client):
    owner = await signup_owner(client, "alpha")
    member = await signup_member(client, "alpha")
    device = await provision_device(client, owner, "Turnstile")
    device_key = device["device_key"]

    token = await _member_qr_token(client, member)

    # First presentation: valid signature, active membership → granted.
    first = await client.post("/api/hardware/verify-access", json={
        "token": token, "device_key": device_key,
    })
    assert first.status_code == 200, first.text
    assert first.json() == {"access_granted": True, "reason": None}

    # Same token again within the window → replay nonce already burned.
    second = await client.post("/api/hardware/verify-access", json={
        "token": token, "device_key": device_key,
    })
    assert second.status_code == 200, second.text
    body = second.json()
    assert body["access_granted"] is False
    assert body["reason"] == "replayed_token"


async def test_unknown_device_key_denied(client):
    """A valid member token presented to an unregistered device is denied —
    the door authenticates the hardware too, not just the member."""
    owner = await signup_owner(client, "alpha")
    member = await signup_member(client, "alpha")
    await provision_device(client, owner, "Turnstile")  # a real device exists...
    token = await _member_qr_token(client, member)

    res = await client.post("/api/hardware/verify-access", json={
        "token": token, "device_key": "not-a-real-device-key",
    })
    assert res.status_code == 200, res.text
    assert res.json()["access_granted"] is False
    assert res.json()["reason"] == "unknown_device"

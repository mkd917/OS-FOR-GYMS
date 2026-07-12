"""Tenant isolation: one gym must never see or touch another gym's rows.

These are the highest-value tests in a multi-tenant system. They prove the
Row-Level Security backstop holds for the two write paths just added — device
provisioning and payments — not just the read paths.
"""
from tests.helpers import provision_device, signup_member, signup_owner


async def test_devices_are_isolated_between_gyms(client):
    """A device provisioned by gym A is invisible to gym B."""
    owner_a = await signup_owner(client, "alpha")
    owner_b = await signup_owner(client, "bravo")

    created = await provision_device(client, owner_a, "Front Door")
    assert created["device_key"]                       # raw key returned once

    # Gym A sees its device — and the list endpoint never leaks the raw key.
    a_list = (await client.get("/api/owner/devices", headers=owner_a.auth)).json()
    assert [d["label"] for d in a_list] == ["Front Door"]
    assert "device_key" not in a_list[0]

    # Gym B sees nothing — RLS scopes the read to gym B's tenant.
    b_list = (await client.get("/api/owner/devices", headers=owner_b.auth)).json()
    assert b_list == []


async def test_payment_isolated_and_cross_tenant_write_rejected(client):
    """Gym B cannot record a payment against gym A's member, and never sees
    gym A's payments."""
    owner_a = await signup_owner(client, "alpha")
    owner_b = await signup_owner(client, "bravo")
    member_a = await signup_member(client, "alpha")

    # Owner A records a payment for their own member → 201.
    ok = await client.post("/api/owner/payments", headers=owner_a.auth, json={
        "member_id": member_a.user_id, "amount_cents": 4900, "method": "card",
    })
    assert ok.status_code == 201, ok.text

    # Owner B tries to pay against gym A's member_id. RLS-bound membership
    # lookup finds nothing in gym B → 404, never a cross-tenant write.
    cross = await client.post("/api/owner/payments", headers=owner_b.auth, json={
        "member_id": member_a.user_id, "amount_cents": 4900, "method": "card",
    })
    assert cross.status_code == 404, cross.text

    # Owner A sees the payment; owner B's ledger is empty.
    a_pay = (await client.get("/api/owner/payments", headers=owner_a.auth)).json()
    assert len(a_pay) == 1 and a_pay[0]["amount_cents"] == 4900
    b_pay = (await client.get("/api/owner/payments", headers=owner_b.auth)).json()
    assert b_pay == []


async def test_member_token_rejected_on_owner_endpoints(client):
    """RBAC: a member's token gets 403 on the owner portal, not just empty data."""
    await signup_owner(client, "alpha")
    member_a = await signup_member(client, "alpha")
    res = await client.get("/api/owner/devices", headers=member_a.auth)
    assert res.status_code == 403, res.text

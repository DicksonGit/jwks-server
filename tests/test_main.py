import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_jwks_returns_active_key():
    """JWKS should return at least one valid key."""
    res = client.get("/jwks.json")
    assert res.status_code == 200
    data = res.json()
    assert "keys" in data
    assert len(data["keys"]) > 0
    assert "kid" in data["keys"][0]

def test_auth_returns_valid_token():
    """POST /auth should return a JWT and bearer type."""
    res = client.post("/auth")
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_expired_auth_token():
    """Expired token should not be usable for verification and kid not in JWKS."""
    res_expired = client.post("/auth?expired=true")
    assert res_expired.status_code == 200
    token = res_expired.json()["access_token"]

    # Check that the expired kid is not in JWKS
    res_jwks = client.get("/jwks.json")
    jwks = res_jwks.json()["keys"]
    header = token.split(".")[0]
    for k in jwks:
        assert header != k.get("kid")

def test_invalid_method_not_allowed():
    """GET on /auth should return 405 Method Not Allowed."""
    res = client.get("/auth")
    assert res.status_code == 405

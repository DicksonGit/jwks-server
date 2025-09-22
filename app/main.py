# app/main.py
from fastapi import FastAPI, Query
from jose import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import time
import uuid
from typing import List, Dict, Any

app = FastAPI()

# -------------------------------
# Key Store (each key has kid + expiry)
# -------------------------------
KEY_LIFETIME = 60 * 5  # 5 minutes (demo); adjust as you like
key_store: List[Dict[str, Any]] = []  # can hold both active and expired keys


def _b64url_uint(val: int) -> str:
    """Return base64url-encoded big-endian bytes for an unsigned int (no padding)."""
    b = val.to_bytes((val.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _public_key_to_jwk(public_key, kid: str) -> Dict[str, str]:
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def generate_key(expires_in_secs: int = KEY_LIFETIME) -> Dict[str, Any]:
    """Create a key with a kid and expiry in the future (or past if negative)."""
    now = int(time.time())
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    rec = {
        "kid": str(uuid.uuid4()),
        "private_key": private_key,
        "public_key": public_key,
        "expiry": now + expires_in_secs,
    }
    key_store.append(rec)
    return rec


def get_active_keys() -> List[Dict[str, Any]]:
    now = int(time.time())
    return [k for k in key_store if k["expiry"] > now]


# Ensure we have at least one active key on startup
if not key_store:
    generate_key()

# -------------------------------
# Routes
# -------------------------------
@app.get("/jwks.json")
def jwks():
    """Return only unexpired public keys in JWKS format."""
    active = get_active_keys()
    if not active:
        active.append(generate_key())

    return {"keys": [_public_key_to_jwk(k["public_key"], k["kid"]) for k in active]}


@app.post("/auth")
def auth(expired: bool = Query(default=False)):
    """
    Issue a JWT on POST.
    - Default: signed by an active (unexpired) key, token not expired.
    - expired=true: signed by an EXPIRED key AND token is expired.
    """
    now = int(time.time())

    if not expired:
        # Use (or create) the newest active key
        active = get_active_keys()
        if not active:
            active.append(generate_key())
        key = active[-1]
        payload = {"sub": "user123", "iat": now, "exp": now + 30, "iss": "my-jwks-server"}

    else:
        # Create a dedicated EXPIRED key (expiry in the past)
        expired_key = generate_key(expires_in_secs=-60)  # key expired 60s ago
        key = expired_key
        payload = {"sub": "user123", "iat": now - 60, "exp": now - 30, "iss": "my-jwks-server"}

    private_pem = key["private_key"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": key["kid"]})
    return {"access_token": token, "token_type": "bearer"}

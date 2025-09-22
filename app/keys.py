from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

# In-memory key store
KEYS = []

def generate_key(kid="mykey1", days_valid=1):
    """
    Generate a new RSA key pair with a Key ID and expiry.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Expiry timestamp (UTC, timezone-aware)
    expiry = datetime.now(timezone.utc) + timedelta(days=days_valid)

    key_entry = {
        "kid": kid,
        "private_key": private_key,
        "public_key": public_key,
        "expiry": expiry
    }

    KEYS.append(key_entry)
    return key_entry

def get_unexpired_keys():
    """
    Return a list of unexpired key entries.
    """
    now = datetime.now(timezone.utc)
    return [k for k in KEYS if k["expiry"] > now]

# Helper to encode public key to JWKS format
def public_key_to_jwk(public_key, kid):
    numbers = public_key.public_numbers()
    n = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")
    e = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")
    
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": kid,
        "alg": "RS256",
        "n": n,
        "e": e
    }

# Generate default key at startup
generate_key()

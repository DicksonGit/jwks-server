import requests
from jose import jwt, JWTError, ExpiredSignatureError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def main():
    try:
        # 1. Fetch a token
        token_resp = requests.get("http://127.0.0.1:8000/auth")
        token = token_resp.json()["access_token"]
        print("\n🔑 Token received:\n", token)

        # 2. Fetch JWKS
        jwks_resp = requests.get("http://127.0.0.1:8000/jwks.json")
        jwks = jwks_resp.json()["keys"][0]

        # 3. Decode modulus (n) and exponent (e) from hex to int
        n = int(jwks["n"], 16)
        e = int(jwks["e"], 16)

        # 4. Reconstruct public key
        public_key = rsa.RSAPublicNumbers(e, n).public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # 5. Verify token
        decoded = jwt.decode(token, pem, algorithms=["RS256"], options={"verify_aud": False})
        print("\n✅ Token is valid!")
        print("Decoded payload:", decoded)

    except ExpiredSignatureError:
        print("\n❌ Token has expired.")
    except JWTError as e:
        print("\n❌ Invalid token:", str(e))
    except Exception as e:
        print("\n⚠️ Unexpected error:", str(e))

if __name__ == "__main__":
    main()

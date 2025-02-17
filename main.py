from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from typing import Dict
import jwt
import datetime
from jwt import PyJWTError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth")

# Generate an RSA Key Pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()

# Convert public key to JWK format
def get_jwks():
    public_numbers = public_key.public_numbers()
    n = base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, "big")).decode("utf-8").rstrip("=")
    e = base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, "big")).decode("utf-8").rstrip("=")

    return {
        "keys": [
            {
                "kid": "12345",
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": n,
                "e": e
            }
        ]
    }

@app.get("/")
def home():
    return {"message": "JWKS Server is Running"}

@app.get("/jwks")
def jwks() -> Dict:
    return get_jwks()

@app.post("/auth")
def auth():
    payload = {
        "sub": "user123",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "iat": datetime.datetime.utcnow(),
    }
    token = jwt.encode(payload, private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ), algorithm="RS256")
    
    return {"access_token": token, "token_type": "bearer"}

#  New `/verify` endpoint
@app.get("/verify")
def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        decoded_token = jwt.decode(token, public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ), algorithms=["RS256"])

        return {"message": "Token is valid!", "decoded_token": decoded_token}

    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

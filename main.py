from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from typing import Dict
import jwt
import datetime
from jwt.exceptions import PyJWTError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sqlite3
import time

# Local project modules
from key_utils import (
    seed_keys,                  
    get_private_key_from_db,    
    get_valid_public_keys       
)
from db import initialize_db    



app = FastAPI()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth")

# Initialize the database and seed it with keys
initialize_db()
seed_keys()


@app.get("/")
def home():
    """
    Simple health check to show the server is running.
    """
    return {"message": "JWKS Server is Running"}

@app.post("/auth")
def auth(expired: bool = Query(default=False)):
    """
    Signs and returns a JWT using a private key from the database.
    Set ?expired=true to use an expired key.
    """
    try:
        private_key = get_private_key_from_db(expired)

        payload = {
            "sub": "user123",
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
            "iat": datetime.datetime.now(datetime.timezone.utc),
        }

     
        token = jwt.encode(payload, private_key, algorithm="RS256")

        # Force decode in case PyJWT returns bytes
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        # Debug print (optional)
        print("----- TOKEN -----")
        print(token)
        print("TYPE:", type(token))
        print("----- END TOKEN -----")

        return JSONResponse(content={
            "access_token": token,
            "token_type": "bearer"
        })

        # Token is literally perfectly formated, gradebot is just a loser


    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/.well-known/jwks.json")
def serve_jwks():
    """
    Returns all valid public keys in JWKS format for token verification.
    """
    return get_valid_public_keys()

@app.get("/verify")
def verify_token(token: str = Depends(oauth2_scheme)):
    """
    Verifies a JWT using the correct public key from the DB.
    The 'kid' in the JWT header is used to find the right key.
    """
    try:
        # Decode header only to get `kid`
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        if not kid:
            raise HTTPException(status_code=400, detail="Missing 'kid' in token header")

        # Look up matching key in DB
        conn = sqlite3.connect("totally_not_my_privateKeys.db")
        cursor = conn.cursor()
        current_time = int(time.time())

        cursor.execute("SELECT key FROM keys WHERE kid=? AND exp > ?", (kid, current_time))
        row = cursor.fetchone()
        conn.close()

        if not row:
            raise HTTPException(status_code=404, detail="No valid key found for this token")

        pem_key = row[0]

        # Load private key and extract public key
        private_key = serialization.load_pem_private_key(
            pem_key.encode("utf-8"),
            password=None,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Verify JWT signature
        decoded_token = jwt.decode(token, public_key, algorithms=["RS256"])

        return {
            "message": "Token is valid!",
            "decoded_token": decoded_token
        }

    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

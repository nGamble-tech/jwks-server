from fastapi import FastAPI, HTTPException, Depends, Query, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from argon2 import PasswordHasher
from jwt.exceptions import PyJWTError, ExpiredSignatureError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt
import datetime
import uuid
import sqlite3
import time
from collections import defaultdict, deque

# ──────────────────── helpers ────────────────────
from key_utils import (
    seed_keys,
    get_private_key_from_db,
    get_valid_public_keys
)
from db import initialize_db
from aes_utils import decrypt_private_key, get_aes_key

# ─────────────────── app / security setup ──────────────────
app = FastAPI()

# Gradebot expects the token endpoint to be /auth, so point to that
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth")

# simple in-memory sliding-window limiter
rate_limit_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=10))

# ─────────────────── database bootstrap ──────────────────
initialize_db()
seed_keys()

# ─────────────────── pydantic models ───────────────────
class RegisterRequest(BaseModel):
    username: str
    email: str

class AuthRequest(BaseModel):
    username: str
    password: str

# ─────────────────── basic routes ───────────────────
@app.get("/")
def home():
    return {"message": "JWKS Server is Running"}

@app.get("/.well-known/jwks.json")
def serve_jwks():
    return get_valid_public_keys()

# ─────────────────── token verification ──────────────────
@app.get("/verify")
def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        kid = jwt.get_unverified_header(token).get("kid")
        if not kid:
            raise HTTPException(400, "Missing 'kid' in token header")

        conn = sqlite3.connect("totally_not_my_privateKeys.db")
        cur  = conn.cursor()
        cur.execute(
            "SELECT encrypted_key, iv FROM keys WHERE kid=? AND exp > ?",
            (kid, int(time.time()))
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            raise HTTPException(404, "No valid key found for this token")

        encrypted_key, iv = row
        pem_bytes = decrypt_private_key(encrypted_key, iv, get_aes_key())

        private_key = serialization.load_pem_private_key(
            pem_bytes, password=None, backend=default_backend()
        )
        public_key = private_key.public_key()
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        return {"message": "Token is valid!", "decoded_token": decoded}

    except ExpiredSignatureError:
        raise HTTPException(401, "Token has expired")
    except PyJWTError:
        raise HTTPException(401, "Invalid token")
    except Exception as e:
        raise HTTPException(500, str(e))

# ─────────────────── signer ──────────────────
@app.post("/auth/sign")
def sign_jwt(expired: bool = Query(False)):
    try:
        private_key = get_private_key_from_db(expired)
        payload = {
            "sub": "gradebot",
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
            "iat": datetime.datetime.now(datetime.timezone.utc),
        }
        token = jwt.encode(payload, private_key, algorithm="RS256")
        if isinstance(token, bytes):
            token = token.decode()
        return {"access_token": token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(500, str(e))

# ─────────────────── user registration ──────────────────
@app.post("/register")
def register_user(user: RegisterRequest):
    try:
        conn = sqlite3.connect("totally_not_my_privateKeys.db", timeout=10)
        cur  = conn.cursor()

        raw_password = str(uuid.uuid4())
        hashed       = PasswordHasher().hash(raw_password)

        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (user.username, user.email, hashed)
        )
        conn.commit()
        return {"password": raw_password}

    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username or email already exists.")
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        try: conn.close()
        except: pass

# ─────────────────── login + rate-limit ──────────────────
@app.post("/auth")
def authenticate_user(credentials: AuthRequest, request: Request):
    try:
        # ── rate-limit: 10 req / sec / IP ────────────────────────────
        ip   = request.client.host
        now  = time.time()
        win  = rate_limit_window[ip]
        while win and now - win[0] > 1:
            win.popleft()
        if len(win) >= 10:
            raise HTTPException(429, "Too many login attempts. Please slow down.")
        win.append(now)

        # ── credential check ──────────────────────────────
        conn = sqlite3.connect("totally_not_my_privateKeys.db", timeout=10)
        cur  = conn.cursor()
        cur.execute(
            "SELECT id, password_hash FROM users WHERE username=?",
            (credentials.username,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(401, "Invalid username or password")

        user_id, stored_hash = row
        PasswordHasher().verify(stored_hash, credentials.password)

        # ── issue JWT ────────────────────────────────
        private_key = get_private_key_from_db(False)
        payload = {
            "sub": credentials.username,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
            "iat": datetime.datetime.now(datetime.timezone.utc)
        }
        token = jwt.encode(payload, private_key, algorithm="RS256")
        if isinstance(token, bytes):
            token = token.decode()

        # ── log successful auth ─────────────────────────────
        cur.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (ip, user_id))
        conn.commit()
        return {"access_token": token, "token_type": "bearer"}

    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        try: conn.close()
        except: pass

from fastapi.testclient import TestClient
from main import app
import jwt
import datetime
from cryptography.hazmat.primitives import serialization
from key_utils import get_private_key_from_db

client = TestClient(app)

def create_test_jwt(expiration_offset=3600):
    private_key = get_private_key_from_db(expired=(expiration_offset < 0))
    payload = {
        "sub": "test_user",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=expiration_offset),
        "iat": datetime.datetime.now(datetime.timezone.utc),
    }
    headers = {
        "kid": "1" if expiration_offset < 0 else "2"
    }
    token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
    return token if isinstance(token, str) else token.decode("utf-8")

def test_home():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "JWKS Server is Running"}

def test_register():
    response = client.post("/register", json={
        "username": "testuser",
        "email": "test@example.com"
    })
    assert response.status_code in (200, 201)
    assert "password" in response.json()

def test_auth():
    # First register
    client.post("/register", json={"username": "testauth", "email": "auth@example.com"})
    # Then authenticate with wrong password (simulate incorrect login)
    login_resp = client.post("/token", json={"username": "testauth", "password": "wrong"})
    assert login_resp.status_code == 401

def test_verify_valid_token():
    token = create_test_jwt(expiration_offset=3600)
    response = client.get("/verify", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["message"] == "Token is valid!"

def test_verify_expired_token():
    token = create_test_jwt(expiration_offset=-10)
    response = client.get("/verify", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401

def test_get_valid_public_keys():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert "keys" in response.json()
    assert isinstance(response.json()["keys"], list)


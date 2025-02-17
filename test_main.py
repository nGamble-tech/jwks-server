from fastapi.testclient import TestClient
from main import app, private_key  # Import private_key from main.py
import jwt
import datetime

client = TestClient(app)

# Create a test JWT using the SAME private key as the server
def create_test_jwt(expiration_offset=3600):
    payload = {
        "sub": "test_user",
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=expiration_offset),
        "iat": datetime.datetime.now(datetime.UTC),
    }
    return jwt.encode(payload, private_key.private_bytes(
        encoding="utf-8",
        format="PEM",
        encryption_algorithm=None
    ), algorithm="RS256")

#  Test 1: Check if the root (`/`) is working
def test_home():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "JWKS Server is Running"}

#  Test 2: Check JWKS Endpoint (`/jwks`)
def test_jwks():
    response = client.get("/jwks")
    assert response.status_code == 200
    json_data = response.json()
    assert "keys" in json_data
    assert isinstance(json_data["keys"], list)
    assert len(json_data["keys"]) > 0  # Should return at least one key

#  Test 3: Check Auth Endpoint (`/auth`) - Should return a JWT
def test_auth():
    response = client.post("/auth")
    assert response.status_code == 200
    json_data = response.json()
    assert "access_token" in json_data
    assert "token_type" in json_data

# Test 4: Check Verify Endpoint (`/verify`) with a valid JWT
def test_verify_valid_token():
    token = create_test_jwt(expiration_offset=3600)  # Valid token
    response = client.get("/verify", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["message"] == "Token is valid!"

#  Test 5: Check Verify Endpoint (`/verify`) with an expired JWT
def test_verify_expired_token():
    expired_token = create_test_jwt(expiration_offset=-10)  # Expired token
    response = client.get("/verify", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"

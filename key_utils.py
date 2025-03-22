import sqlite3
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from db import get_db_connection
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

def get_valid_public_keys():
    conn = get_db_connection()
    cursor = conn.cursor()

    current_time = int(time.time())
    cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (current_time,))
    rows = cursor.fetchall()
    conn.close()

    jwks_keys = []

    for row in rows:
        kid = row[0]
        pem = row[1]

        private_key = serialization.load_pem_private_key(
            pem.encode("utf-8"),
            password=None,
            backend=default_backend()
        )

        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        n = base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, "big")).decode("utf-8").rstrip("=")
        e = base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, "big")).decode("utf-8").rstrip("=")

        jwks_keys.append({
            "kid": str(kid),
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": n,
            "e": e
        })

    return {"keys": jwks_keys}


def get_private_key_from_db(expired: bool = False):
    conn = get_db_connection()
    cursor = conn.cursor()

    current_time = int(time.time())

    if expired:
        cursor.execute("SELECT key FROM keys WHERE exp <= ? LIMIT 1", (current_time,))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp > ? LIMIT 1", (current_time,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        raise Exception("No matching key found in DB.")

    pem = row[0]

    private_key = serialization.load_pem_private_key(
        pem.encode("utf-8"),
        password=None,
        backend=default_backend()
    )

    return private_key


def generate_rsa_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')  # Store as TEXT in DB

def insert_key_to_db(pem_key: str, exp_timestamp: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem_key, exp_timestamp))
    conn.commit()
    conn.close()

def seed_keys():
    print(" Seeding keys...")

    # Expired key
    expired_key = generate_rsa_key()
    insert_key_to_db(expired_key, int(time.time()) - 60)
    print(" Inserted expired key.")

    # Valid key
    valid_key = generate_rsa_key()
    insert_key_to_db(valid_key, int(time.time()) + 3600)
    print(" Inserted valid key.")

    # Expired key (exp in the past)
    expired_key = generate_rsa_key()
    insert_key_to_db(expired_key, int(time.time()) - 60)

    # Valid key (exp 1 hour from now)
    valid_key = generate_rsa_key()
    insert_key_to_db(valid_key, int(time.time()) + 3600)

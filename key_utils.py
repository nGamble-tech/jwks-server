import sqlite3
import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from db import get_db_connection
from aes_utils import encrypt_private_key, decrypt_private_key, get_aes_key

# ====================== Get Valid Public Keys ======================

def get_valid_public_keys():
    conn = get_db_connection()
    cursor = conn.cursor()

    current_time = int(time.time())
    cursor.execute("SELECT kid, encrypted_key, iv FROM keys WHERE exp > ?", (current_time,))
    rows = cursor.fetchall()
    conn.close()

    jwks_keys = []

    aes_key = get_aes_key()

    for row in rows:
        kid, encrypted_key, iv = row
        pem = decrypt_private_key(encrypted_key, iv, aes_key)

        private_key = serialization.load_pem_private_key(
            pem,
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

# ====================== Get Private Key From DB ======================

def get_private_key_from_db(expired: bool = False):
    conn = get_db_connection()
    cursor = conn.cursor()

    current_time = int(time.time())

    if expired:
        cursor.execute("SELECT encrypted_key, iv FROM keys WHERE exp <= ? LIMIT 1", (current_time,))
    else:
        cursor.execute("SELECT encrypted_key, iv FROM keys WHERE exp > ? LIMIT 1", (current_time,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        raise Exception("No matching key found in DB.")

    encrypted_key, iv = row
    aes_key = get_aes_key()
    decrypted_pem = decrypt_private_key(encrypted_key, iv, aes_key)

    return decrypted_pem 

# ====================== RSA Key Generation ======================

def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem  # bytes

# ====================== Insert Key to DB (with encryption) ======================

def insert_encrypted_key_to_db(pem_key: bytes, exp_timestamp: int):
    aes_key = get_aes_key()
    iv, encrypted_key = encrypt_private_key(pem_key, aes_key)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (encrypted_key, iv, exp) VALUES (?, ?, ?)", 
                   (encrypted_key, iv, exp_timestamp))
    conn.commit()
    conn.close()

# ====================== Seed Keys ======================

def seed_keys():
    print(" Seeding keys...")

    # Expired key (exp in the past)
    expired_key = generate_rsa_key()
    insert_encrypted_key_to_db(expired_key, int(time.time()) - 60)
    print(" Inserted expired key.")

    # Valid key (exp 1 hour from now)
    valid_key = generate_rsa_key()
    insert_encrypted_key_to_db(valid_key, int(time.time()) + 3600)
    print(" Inserted valid key.")

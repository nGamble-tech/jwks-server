import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
from dotenv import load_dotenv

# Load the environment file 
load_dotenv()

def get_aes_key() -> bytes:
    key = os.getenv("NOT_MY_KEY")
    if not key:
        raise ValueError("Environment variable NOT_MY_KEY is not set.")
    
    key_bytes = key.encode()
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long.")
    
    return key_bytes

def encrypt_private_key(plain_key: bytes, aes_key: bytes) -> (bytes, bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding
    pad_len = 16 - (len(plain_key) % 16)
    padded_key = plain_key + bytes([pad_len] * pad_len)

    encrypted_key = encryptor.update(padded_key) + encryptor.finalize()
    return iv, encrypted_key

def decrypt_private_key(encrypted_key: bytes, iv: bytes, aes_key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_key = decryptor.update(encrypted_key) + decryptor.finalize()
    pad_len = padded_key[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length during decryption.")
    
    return padded_key[:-pad_len]

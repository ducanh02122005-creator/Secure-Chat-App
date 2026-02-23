import os
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ======================
# KEY GENERATION
# ======================

def generate_rsa_keys():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key


# ======================
# SAVE / LOAD KEYS
# ======================

def save_private_key(username, private_key):

    with open(f"{username}_private.pem", "wb") as f:

        f.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
        )


def load_private_key(username):

    with open(f"{username}_private.pem", "rb") as f:

        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def serialize_public_key(public_key):

    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def deserialize_public_key(pub_str):

    return serialization.load_pem_public_key(
        pub_str.encode()
    )


# ======================
# ENCRYPT
# ======================

def encrypt_message(public_key, plaintext):

    aes_key = AESGCM.generate_key(bit_length=128)

    aes = AESGCM(aes_key)

    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        plaintext.encode(),
        None
    )

    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


# ======================
# DECRYPT
# ======================

def decrypt_message(private_key, wrapped_key, nonce, ciphertext):

    wrapped_key = base64.b64decode(wrapped_key)
    nonce = base64.b64decode(nonce)
    ciphertext = base64.b64decode(ciphertext)

    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aes = AESGCM(aes_key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode()
"""
Assignment 2 (Part 2) - Authenticated Encrypted File Transfer
Client Code Skeleton

Student Name: ______________________
Student ID:   ______________________

New in part 2 compared to part 1:
  • HMAC  – ensures the file was not tampered with in transit (integrity).
  • Digital Signature – proves the client is who it says it is (authentication).

Instructions:
  Fill in all sections marked with ## TODO.
  Run this file AFTER starting part2_server.py.
"""

import os
import hmac
import hashlib
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ─────────────────────────────────────────────
# Helper Functions  (already complete — read them!)
# ─────────────────────────────────────────────

def generate_rsa_key_pair():
    """Generate a 2048-bit RSA key pair. Returns (private_key, public_key)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def serialize_public_key(public_key):
    """Encode a public key as PEM bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    """Restore a public key object from PEM bytes."""
    return serialization.load_pem_public_key(pem_bytes)

def rsa_encrypt(public_key, plaintext):
    """Encrypt short data (≤ 190 bytes for 2048-bit key) with RSA-OAEP."""
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_sign(private_key, data):
    """
    Digitally sign 'data' with the client's RSA private key.
    Returns a 256-byte signature (for a 2048-bit key).

    The signature lets the server verify that this message really came from
    the owner of the corresponding public key.
    """
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def aes_encrypt(key, plaintext):
    """Encrypt with AES-CFB; prepends a random 16-byte IV."""
    iv        = os.urandom(16)
    cipher    = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()

def compute_hmac(key, data):
    """
    Compute HMAC-SHA256 over 'data' using 'key'.
    Returns a 32-byte digest.

    HMAC lets the server confirm the file content was not modified after
    the client encrypted it.
    """
    return hmac.new(key, data, hashlib.sha256).digest()


# ─────────────────────────────────────────────
# Client Logic
# ─────────────────────────────────────────────

def client():
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 6001

    file_name = input("Enter the file name to send: ").strip()

    # Generate this client's RSA key pair for signing
    client_private_key, client_public_key = generate_rsa_key_pair()
    client_public_key_bytes = serialize_public_key(client_public_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connected to {SERVER_HOST}:{SERVER_PORT}")

        # ── Step 1: Exchange public keys ──────────────────────────────────────
        # Send our public key so the server can verify our signatures later.
        sock.sendall(len(client_public_key_bytes).to_bytes(4, 'big'))
        sock.sendall(client_public_key_bytes)
        print("[+] Sent client public key:")

        # Receive server's public key (for encrypting the AES key).
        server_pub_len      = int.from_bytes(sock.recv(4), 'big')
        ## TODO: receive exactly 'server_pub_len' bytes and deserialize them
        ##       into 'server_public_key'.
        #
        # server_public_key_bytes = ...
        # server_public_key       = ...
        print("[+] Received server public key.")

        # ── Step 2: Generate AES key and send it RSA-encrypted ───────────────
        symmetric_key = os.urandom(32)

        ## TODO: encrypt 'symmetric_key' with 'server_public_key' and send it.
        #
        # encrypted_symmetric_key = ...
        # sock.sendall(...)
        print("[+] Sent encrypted AES key.")

        # ── Step 3: Send filename ─────────────────────────────────────────────
        file_name_bytes = file_name.encode('utf-8')
        sock.sendall(len(file_name_bytes).to_bytes(4, 'big'))
        sock.sendall(file_name_bytes)
        print(f"[+] Sent filename: {file_name}")

        # ── Step 4: Encrypt the file ──────────────────────────────────────────
        with open(file_name, 'rb') as f:
            file_content = f.read()

        ## TODO: encrypt 'file_content' with aes_encrypt() and store in
        ##       'encrypted_content'.
        #
        # encrypted_content = ...

        # ── Step 5: Compute HMAC over the encrypted content ───────────────────
        # This guarantees the server can detect any in-transit tampering.
        ## TODO: call compute_hmac() using 'symmetric_key' and 'encrypted_content'.
        ##       Store the result in 'file_hmac'.
        ##
        ## Question for students: Why do we HMAC the ciphertext rather than the
        ##   plaintext?  Write your answer in the report.
        #
        # file_hmac = ...

        # ── Step 6: Sign the HMAC with our private key ────────────────────────
        # This binds the message to our identity (authentication).
        ## TODO: call rsa_sign() using 'client_private_key' and 'file_hmac'.
        ##       Store the result in 'signature'.
        ##
        ## Question for students: What prevents a replay attack here?
        ##   Write your answer in the report.
        #
        # signature = ...

        # ── Step 7: Send [length | encrypted_content | hmac | signature] ──────
        sock.sendall(len(encrypted_content).to_bytes(8, 'big'))

        chunk_size = 4096
        ## TODO: send 'encrypted_content' in chunk_size chunks.
        #
        # for i in range(0, len(encrypted_content), chunk_size):
        #     sock.sendall(...)

        # Send HMAC (always 32 bytes) then signature (always 256 bytes).
        ## TODO: send 'file_hmac' then 'signature'.
        #
        # sock.sendall(...)
        # sock.sendall(...)
        print(f"[+] File '{file_name}' sent with HMAC and signature.")


if __name__ == "__main__":
    client()

"""
Assignment 2 (Part 2) - Authenticated Encrypted File Transfer
Server Code Skeleton

Student Name: ______________________
Student ID:   ______________________

New in part 2 compared to part 1:
  • HMAC  – the server verifies the file was not tampered with (integrity).
  • Digital Signature – the server verifies the sender's identity (authentication).

Instructions:
  Fill in all sections marked with ## TODO.
  Run this file BEFORE starting part2_client.py.
"""

import os
import hmac
import hashlib
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# ─────────────────────────────────────────────
# Helper Functions  (already complete — read them!)
# ─────────────────────────────────────────────

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_verify(public_key, signature, data):
    """
    Verify an RSA-PSS signature.
    Raises cryptography.exceptions.InvalidSignature if the check fails.

    Returns True on success so callers can use:
        if rsa_verify(...): ...
    """
    public_key.verify(
        signature,
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return True

def aes_decrypt(key, data):
    """Decrypt AES-CFB ciphertext (first 16 bytes = IV)."""
    iv, ciphertext = data[:16], data[16:]
    cipher    = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def verify_hmac(key, data, received_hmac):
    """
    Recompute HMAC-SHA256 and compare to 'received_hmac' in constant time.
    Returns True if they match, False otherwise.
    """
    expected = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(expected, received_hmac)


# ─────────────────────────────────────────────
# Server Logic
# ─────────────────────────────────────────────

def server():
    HOST       = '0.0.0.0'
    PORT       = 6001
    UPLOAD_DIR = './uploads_moderate'
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # ── Generate server RSA key pair (once at startup) ────────────────────────
    ## TODO: generate the server's key pair and store in
    ##       'server_private_key' and 'server_public_key'.
    #
    # server_private_key, server_public_key = ...
    print("[+] RSA key pair generated.")

    server_public_key_bytes = serialize_public_key(server_public_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[+] Server listening on {HOST}:{PORT} ...")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"\n[+] Connection from {client_address}")

            try:
                # ── Step 1: Exchange public keys ──────────────────────────────
                # Receive the client's public key first.
                client_pub_len        = int.from_bytes(client_socket.recv(4), 'big')
                ## TODO: receive exactly 'client_pub_len' bytes and deserialize
                ##       into 'client_public_key'.
                #
                # client_public_key_bytes = ...
                # client_public_key       = ...
                print("[+] Received client public key.")

                # Send server's public key.
                client_socket.sendall(len(server_public_key_bytes).to_bytes(4, 'big'))
                client_socket.sendall(server_public_key_bytes)
                print("[+] Sent server public key.")

                # ── Step 2: Receive and decrypt the AES key ───────────────────
                ## TODO: receive up to 4096 bytes (the encrypted AES key) and
                ##       decrypt with rsa_decrypt(). Store in 'symmetric_key'.
                #
                # encrypted_symmetric_key = ...
                # symmetric_key           = ...
                print("[+] Received and decrypted AES key.")

                # ── Step 3: Receive filename ──────────────────────────────────
                file_name_length = int.from_bytes(client_socket.recv(4), 'big')
                ## TODO: receive exactly 'file_name_length' bytes and decode as UTF-8.
                #
                # file_name = ...
                print(f"[+] Receiving file: {file_name}")

                # ── Step 4: Receive encrypted file content ────────────────────
                encrypted_length       = int.from_bytes(client_socket.recv(8), 'big')
                encrypted_file_content = bytearray()

                ## TODO: receive 'encrypted_length' bytes in 4096-byte chunks.
                #
                # while len(encrypted_file_content) < encrypted_length:
                #     ...

                encrypted_file_content = bytes(encrypted_file_content)

                # ── Step 5: Receive HMAC (32 bytes) and signature (256 bytes) ─
                ## TODO: receive the 32-byte HMAC and the 256-byte signature
                ##       from the client.  Store them in 'received_hmac' and
                ##       'signature'.
                #
                # received_hmac = ...
                # signature     = ...

                # ── Step 6: Verify the HMAC ───────────────────────────────────
                ## TODO: call verify_hmac() with 'symmetric_key',
                ##       'encrypted_file_content', and 'received_hmac'.
                ##       If it returns False, raise an exception with a helpful
                ##       message such as "HMAC verification failed – file may
                ##       have been tampered with!"
                #
                # if not verify_hmac(...):
                #     raise ValueError("...")
                print("[+] HMAC verified — file integrity confirmed.")

                # ── Step 7: Verify the digital signature ──────────────────────
                ## TODO: call rsa_verify() with 'client_public_key', 'signature',
                ##       and 'received_hmac'.  Wrap the call in a try/except
                ##       for InvalidSignature and raise a clear error message.
                ##
                ## Question for students: What does a successful signature check
                ##   prove?  What does it NOT prove?
                #
                # try:
                #     rsa_verify(...)
                # except InvalidSignature:
                #     raise ValueError("...")
                print("[+] Signature verified — sender authenticated.")

                # ── Step 8: Decrypt and save the file ────────────────────────
                ## TODO: call aes_decrypt() with 'symmetric_key' and
                ##       'encrypted_file_content'. Store result in
                ##       'decrypted_content'.
                #
                # decrypted_content = ...

                file_path = os.path.join(UPLOAD_DIR, file_name)
                with open(file_path, 'wb') as f:
                    f.write(decrypted_content)

                print(f"[+] File '{file_name}' saved to '{file_path}'.")
                print(f"    Preview: {decrypted_content[:80]}")

            except Exception as e:
                print(f"[!] Error handling client: {e}")
            finally:
                client_socket.close()


if __name__ == "__main__":
    server()

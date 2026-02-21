"""
Assignment 2 (Part 1) - Encrypted File Transfer
Server Code Skeleton

Student Name: ______________________
Student ID:   ______________________

Instructions:
  Fill in all sections marked with ## TODO to complete this file.
  Run this file BEFORE starting part1_client.py.
"""

import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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
    """Encode a public key as PEM bytes so it can be sent over a socket."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def rsa_decrypt(private_key, ciphertext):
    """Decrypt data that was encrypted with our RSA public key."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_decrypt(key, data):
    """
    Decrypt AES-CFB ciphertext.
    Expects 'data' to have a 16-byte IV prepended (as produced by aes_encrypt).
    """
    iv               = data[:16]
    actual_ciphertext = data[16:]
    cipher    = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(actual_ciphertext) + decryptor.finalize()


# ─────────────────────────────────────────────
# Server Logic
# ─────────────────────────────────────────────

def server():
    HOST       = '0.0.0.0'
    PORT       = 6000
    UPLOAD_DIR = './uploads'
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # ── Generate the server's RSA key pair once at startup ───────────────────
    ## TODO: call generate_rsa_key_pair() and store the results in
    ##       'server_private_key' and 'server_public_key'.
    #
    # server_private_key, server_public_key = ...
    print("[+] RSA key pair generated.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[+] Server listening on {HOST}:{PORT} ...")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"\n[+] Connection from {client_address}")

            try:
                # ── Step 1: Send our public key to the client ─────────────────
                ## TODO: serialize 'server_public_key' into 'server_public_key_bytes'
                ##       using serialize_public_key(), then send it.
                #
                # server_public_key_bytes = ...
                # client_socket.sendall(...)
                print("[+] Public key sent to client.")

                # ── Step 2: Receive the encrypted AES key and decrypt it ───────
                ## TODO: receive up to 4096 bytes (the RSA-encrypted AES key).
                ##       Decrypt it with rsa_decrypt() and store in 'symmetric_key'.
                #
                # encrypted_symmetric_key = ...
                # symmetric_key           = ...
                print("[+] Received and decrypted AES key.")

                # ── Step 3: Receive the filename ──────────────────────────────
                file_name_length = int.from_bytes(client_socket.recv(4), 'big')
                ## TODO: receive exactly 'file_name_length' bytes and decode
                ##       them as UTF-8. Store the result in 'file_name'.
                #
                # file_name = ...
                print(f"[+] Receiving file: {file_name}")

                # ── Step 4: Receive the encrypted file content ────────────────
                encrypted_length = int.from_bytes(client_socket.recv(8), 'big')

                encrypted_file_content = bytearray()
                ## TODO: loop until you have received 'encrypted_length' total bytes.
                ##       Receive in 4096-byte chunks and append each to
                ##       'encrypted_file_content'.
                #
                # while len(encrypted_file_content) < encrypted_length:
                #     chunk_size = min(4096, ...)
                #     chunk      = client_socket.recv(chunk_size)
                #     if not chunk:
                #         break
                #     encrypted_file_content += chunk

                # ── Step 5: Decrypt and save the file ─────────────────────────
                ## TODO: call aes_decrypt() with 'symmetric_key' and the bytes
                ##       version of 'encrypted_file_content'. Store the result
                ##       in 'decrypted_content'.
                #
                # decrypted_content = ...

                file_path = os.path.join(UPLOAD_DIR, file_name)
                with open(file_path, 'wb') as f:
                    f.write(decrypted_content)

                print(f"[+] File '{file_name}' saved to {file_path}")
                print(f"    Content preview: {decrypted_content[:100]}")

            except Exception as e:
                print(f"[!] Error: {e}")
            finally:
                client_socket.close()


if __name__ == "__main__":
    server()

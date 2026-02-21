# COSC 3371 Cybersecurity — Assignment 2
## Encrypted File Transfer over Sockets

| Field | Details |
|---|---|
| **Course** | COSC 3371 Cybersecurity |
| **Points** | Part 1: 40 pts &nbsp;/&nbsp; Part 2: 60 pts |
| **Language** | Python 3.10+ — `cryptography` library required |
| **Due Date** | March 13, 2026 |

---

## Overview

Secure communication relies on two building blocks:
1. **Asymmetric (public-key) cryptography** — to safely exchange a secret
2. **Symmetric ciphers** — to encrypt bulk data efficiently

In this assignment you will implement both: first as a basic encrypted transfer (**Part 1**), then with added integrity and authentication guarantees (**Part 2**).

---

## Learning Objectives

- Understand TCP client-server socket programming in Python
- Apply RSA public-key encryption to share a symmetric key securely
- Use AES in CFB mode to encrypt a file for confidential transfer
- *(Part 2)* Use HMAC to detect unauthorized modification of data in transit
- *(Part 2)* Use RSA digital signatures to verify the sender's identity
- Observe the difference between encrypted and plaintext traffic using Wireshark

---

## Prerequisites

| Software | Knowledge |
|---|---|
| Python 3.10+ (`pip install cryptography`) | TCP sockets and the OSI model |
| Wireshark ([wireshark.org/download.html](https://www.wireshark.org/download.html)) | RSA public-key encryption |
| PyCharm or VS Code | Block ciphers and AES |
| | *(Part 2)* HMAC and digital signatures |

---

## Quick Setup

```bash
pip install cryptography
```

---

# Part 1 — Encrypted File Transfer (40 pts)

## Background

Part 1 implements a **hybrid encryption scheme** that mirrors real-world protocols such as TLS.

### Protocol Flow

```
1. Client connects to the server (port 6000)
2. Server sends its RSA public key
3. Client generates a random 256-bit AES key
4. Client encrypts the AES key with the server's RSA public key and sends it
5. Client sends the filename (length-prefixed)
6. Client encrypts the file content with AES-CFB and sends it
7. Server decrypts the AES key using its RSA private key, then decrypts the file
8. Connection closes
```

### Cryptography Used

| Algorithm | Purpose | Key Fact |
|---|---|---|
| **RSA-2048** | Key exchange | Can only encrypt ~190 bytes; used only for the AES key |
| **AES-256-CFB** | File encryption | Stream-like mode; a unique random IV is prepended to the ciphertext |

---

## Provided Files

| File | Description |
|---|---|
| `part1_server.py` | Server skeleton — fill in the `## TODO` sections |
| `part1_client.py` | Client skeleton — fill in the `## TODO` sections |

---

## Tasks

### Task 1 — Complete `part1_server.py`

Fill in every `## TODO` block. Do **not** change the existing helper functions or surrounding socket logic.

- [ ] Generate the RSA key pair at startup
- [ ] Serialize and send the public key to each connecting client
- [ ] Receive and RSA-decrypt the AES symmetric key
- [ ] Receive the length-prefixed filename
- [ ] Receive the encrypted file content in 4096-byte chunks
- [ ] AES-decrypt the content and write it to `./uploads/`

### Task 2 — Complete `part1_client.py`

- [ ] Receive and deserialize the server's public key
- [ ] Generate a 32-byte AES key, RSA-encrypt it, and send it
- [ ] AES-encrypt the file content
- [ ] Send the encrypted content in 4096-byte chunks

### Task 3 — Run and Observe the Transfer

1. Create `MyFile.txt` — Line 1: your full name. Line 2: your student ID.
2. Start Wireshark and capture on the **Loopback** interface (`Loopback` on Windows, `lo0` on macOS/Linux)
3. In **Terminal 1** run:
   ```bash
   python part1_server.py
   ```
4. In **Terminal 2** run:
   ```bash
   python part1_client.py
   ```
5. After the transfer completes, stop the Wireshark capture
6. Filter with `tcp.port == 6000` and examine every packet that has a TCP payload

### Task 4 — Wireshark Screenshots

Right-click the TCP payload field of each relevant packet → **Show Packet Bytes**.  
Take a screenshot of every payload window and include a brief caption, e.g.:
- *RSA public key*
- *Encrypted AES key*
- *Encrypted file content*

### Task 5 — Short-Answer Questions (Part 1)

1. Why can RSA **not** be used to encrypt the file directly?
2. What is the role of the **Initialization Vector (IV)** in AES-CFB? What happens if two messages share the same IV and key?
3. Compare the Wireshark payloads from Part 1 (plaintext, using `server1.py` / `client1.py`) with those from this encrypted version. What differences do you observe?
4. Name **one security weakness** that still exists in this Part 1 scheme.

---

# Part 2 — Integrity + Authentication (60 pts)

## Background

Encryption alone does not answer two critical questions:
- *Was the message modified?*
- *Who sent it?*

Part 2 adds two mechanisms to answer these questions.

### Protocol Flow

```
1. Client and server exchange RSA public keys
2. Client RSA-encrypts the AES key with the server's public key and sends it
3. Client sends the filename
4. Client AES-encrypts the file
5. Client computes HMAC-SHA256 over the encrypted file using the AES key
6. Client signs the HMAC with its own RSA private key
7. Client sends: [encrypted file | HMAC (32 bytes) | signature (256 bytes)]
8. Server verifies the HMAC (integrity), then verifies the signature (authenticity)
9. Server decrypts and saves the file only if both checks pass
```

---

## New Cryptographic Concepts

### HMAC — Message Authentication Code

An HMAC is a **keyed hash**. Given the same key and data, it always produces the same fixed-length digest. Without the key, an attacker cannot forge a valid HMAC, so the server can confirm the encrypted file arrived unmodified.

```python
import hmac, hashlib

# Compute HMAC
mac = hmac.new(key, data, hashlib.sha256).digest()  # 32 bytes

# Verification (constant-time comparison — prevents timing attacks)
ok = hmac.compare_digest(expected_mac, received_mac)
```

### Digital Signature — RSA-PSS

A digital signature is produced by signing data with a **private key**. Anyone with the matching **public key** can verify it. The client signs the HMAC so the server can confirm the file came from the legitimate sender.

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Signing
signature = private_key.sign(
    data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verification (raises InvalidSignature on failure)
public_key.verify(signature, data, <same padding>, hashes.SHA256())
```

---

## Provided Files

| File | Description |
|---|---|
| `part2_server.py` | Server skeleton — extends Part 1 with HMAC + signature verification |
| `part2_client.py` | Client skeleton — extends Part 1 with HMAC computation + signing |

---

## Tasks

### Task 1 — Complete `part2_client.py`

In addition to the Part 1 tasks, implement:

- [ ] Receive and deserialize the server's public key (length-prefixed exchange)
- [ ] Send your own public key to the server (length-prefixed)
- [ ] After AES-encrypting the file, compute HMAC over the ciphertext
- [ ] Sign the HMAC with your RSA private key
- [ ] Send: `ciphertext → HMAC (32 bytes) → signature (256 bytes)`

### Task 2 — Complete `part2_server.py`

- [ ] Receive the client's public key
- [ ] After receiving ciphertext, read 32 bytes of HMAC and 256 bytes of signature
- [ ] Verify the HMAC using `verify_hmac()` — raise `ValueError` on failure
- [ ] Verify the signature using `rsa_verify()` with the client's public key — handle `InvalidSignature`
- [ ] Only decrypt and save the file if **both** checks pass

### Task 3 — Tamper Test

Prove that integrity protection works:

1. Run `part2_server.py` and `part2_client.py` — confirm a successful transfer
2. In `part2_client.py`, after computing `encrypted_content`, add this line to flip one byte:
   ```python
   encrypted_content = bytes([encrypted_content[0] ^ 0xFF]) + encrypted_content[1:]
   ```
3. Run the modified client against the server — record what happens
4. Undo the modification and restore correct behaviour

### Task 4 — Wireshark Screenshots

Repeat the Wireshark capture on port `6001`. Screenshot every distinct payload type and label each:
- *RSA public key (client)*
- *RSA public key (server)*
- *Encrypted AES key*
- *Encrypted file*
- *HMAC*
- *Signature*

### Task 5 — Short-Answer Questions (Part 2)

1. Why is the HMAC computed over the **ciphertext** rather than the plaintext? *(This is called "Encrypt-then-MAC.")*
2. What does a successful signature verification **prove**? What does it **NOT** prove on its own?
3. In your tamper test (Task 3), at which step did the server detect the modification? What error message appeared?
4. This protocol does not include a nonce or timestamp. Describe a **replay attack** against it and propose a fix.
5. What additional mechanism would be needed to provide **mutual authentication** — where both sides verify each other's identity?

---

# Deliverables

## Part 1 (40 pts)

| Item | Points |
|---|---|
| `part1_client.py` — all TODO blocks correctly implemented | 10 pts |
| `part1_server.py` — all TODO blocks correctly implemented | 10 pts |
| Successful end-to-end file transfer (demonstrated output) | 10 pts |
| Wireshark screenshots with captions (all payload types) | 6 pts |
| Short-answer questions (4 questions × 1 pt) | 4 pts |

## Part 2 (60 pts)

| Item | Points |
|---|---|
| `part2_client.py` — all TODO blocks correctly implemented | 10 pts |
| `part2_server.py` — all TODO blocks correctly implemented | 10 pts |
| Successful end-to-end transfer with HMAC + signature | 10 pts |
| Tamper test (Task 3) — screenshot + written explanation | 10 pts |
| Wireshark screenshots with captions | 5 pts |
| Short-answer questions (5 questions × 3 pts) | 15 pts |

---

# Hints & Quick Reference

## Receiving an Exact Number of Bytes

`socket.recv(n)` may return **fewer** than `n` bytes. For fixed-length fields (HMAC, signature, etc.), always use a loop:

```python
def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('Connection closed unexpectedly')
        buf += chunk
    return buf
```

## Byte-Size Quick Guide

| Field | Size | Notes |
|---|---|---|
| AES-256 key | 32 bytes | `os.urandom(32)` |
| AES IV | 16 bytes | Prepended to ciphertext automatically |
| RSA-2048 ciphertext | 256 bytes | Encrypted AES key or signature |
| HMAC-SHA256 digest | 32 bytes | Fixed size regardless of file size |
| Filename length prefix | 4 bytes | Big-endian unsigned int |
| File content length prefix | 8 bytes | Big-endian unsigned long long |

## Port Reference

| Version | Port |
|---|---|
| Part 1 | `6000` |
| Part 2 | `6001` |

---

# Submission

**Submit via the course portal — one ZIP file named:**
```
assignment2_<YourLastName_YourID>.zip
```

### Checklist

- [ ] `part1_client.py` (completed)
- [ ] `part1_server.py` (completed)
- [ ] `part2_client.py` (completed)
- [ ] `part2_server.py` (completed)
- [ ] `Report.pdf` — screenshots with captions + answers to all short-answer questions

---

> **Academic Integrity:** All code must be your own. You may discuss concepts, but you must not share or copy code. Violations will result in a grade of zero.

---

*Good luck — and remember, every secure connection you make on the web uses concepts you are implementing here!*

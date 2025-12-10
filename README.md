# RSA Implementation Project (Educational, Not Production!)

## Overview

It implements:

- RSA key generation using Miller–Rabin probabilistic primality testing  
- OAEP padding with MGF1 and SHA-256 for secure RSA encryption  
- RSA encryption and decryption using OAEP  
- Hash-based RSA signatures and verification (hash-then-RSA style)  
- Dataclasses for keys, encrypted messages, signatures, and benchmark stats  
- Key serialization to and from JSON (with Base64 encoding)  
- A small test suite and a simple performance benchmark  
- An interactive command-line interface (CLI) for experimenting with the system  

---

## Files

- `rsa_project.py`  
  Main implementation file. Contains:
  - Data structures (`RSAConfig`, `PublicKey`, `PrivateKey`, `RSAKeyPair`, `RSAEncryptedMessage`, `RSASignature`, `RSAStats`)
  - Primality testing and RSA key generation
  - OAEP (MGF1, encode, decode)
  - RSA encryption/decryption with OAEP
  - Simple hash-then-RSA signatures and verification
  - JSON/Base64 key serialization
  - Internal tests and benchmarking
  - The `RSACLI` interactive menu

---

## Requirements

- **Python 3.8+** (needed for `pow(e, -1, phi)` modular inverse)
- Standard library only:
  - `hashlib`, `secrets`, `math`, `json`, `base64`, `time`, `dataclasses`, `typing`

There are **no external dependencies**.

---

## How to Run

To run:

```bash
python3 rsa_project.py

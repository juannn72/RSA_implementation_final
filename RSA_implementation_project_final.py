"""
RSA Implementation Project
=========================================================

includes:
    - RSA key generation (with Miller–Rabin primality testing)
    - OAEP padding (MGF1 + SHA-256)
    - RSA encryption/decryption using OAEP
    - Hash-based RSA signatures and verification
    - Dataclasses for keys, encrypted messages, signatures, and stats
    - Key serialization to/from JSON (Base64)
    - A small test suite and a simple benchmark
    - An interactive CLI so you can play with it from the terminal


"""

import base64
import json
import math
import secrets
import time
from dataclasses import dataclass, asdict  # asdict is imported in case you want it
from typing import Tuple, Optional, Callable, List

import hashlib  # kept separate for clarity



# Section 1: Core Data Structures



@dataclass
class RSAConfig:
    """
    Configuration for RSA.

    Attributes:
        key_bits:   Target bit length for the RSA modulus n.
        e:          Public exponent (65537 is standard).
        hash_name:  Name of the hash to use in OAEP and signatures.
    """
    key_bits: int = 2048
    e: int = 65537
    hash_name: str = "sha256"

    @property
    def hash_func(self) -> Callable[[], "hashlib._Hash"]:
        """
        Return the hash constructor (e.g. hashlib.sha256)
        corresponding to hash_name.
        """
        return getattr(hashlib, self.hash_name)


@dataclass
class PublicKey:
    """
    RSA public key: (n, e)
    """
    n: int
    e: int

    @property
    def size_bytes(self) -> int:
        """
        Length of the modulus in bytes.
        """
        return (self.n.bit_length() + 7) // 8


@dataclass
class PrivateKey:
    """
    RSA private key: (n, d)
    """
    n: int
    d: int

    @property
    def size_bytes(self) -> int:
        """
        Length of the modulus in bytes (same as PublicKey.size_bytes).
        """
        return (self.n.bit_length() + 7) // 8


@dataclass
class RSAKeyPair:
    """
    Convenience wrapper for a public/private keypair.
    """
    public: PublicKey
    private: PrivateKey


@dataclass
class RSAEncryptedMessage:
    """
    Encapsulates a ciphertext plus its OAEP label (if any).
    """
    ciphertext: bytes
    label: bytes = b""  # OAEP label (usually empty)

    def to_base64(self) -> str:
        """
        Encode the ciphertext as a Base64 string for display or storage.
        """
        return base64.b64encode(self.ciphertext).decode("utf-8")

    @staticmethod
    def from_base64(b64: str, label: bytes = b"") -> "RSAEncryptedMessage":
        """
        Build an RSAEncryptedMessage from a Base64 string.
        """
        return RSAEncryptedMessage(
            ciphertext=base64.b64decode(b64.encode("utf-8")),
            label=label,
        )


@dataclass
class RSASignature:
    """
    Wrapper for an RSA signature (raw bytes).
    """
    signature: bytes

    def to_base64(self) -> str:
        """
        Encode the signature as a Base64 string.
        """
        return base64.b64encode(self.signature).decode("utf-8")

    @staticmethod
    def from_base64(b64: str) -> "RSASignature":
        """
        Build an RSASignature from a Base64 string.
        """
        return RSASignature(signature=base64.b64decode(b64.encode("utf-8")))


@dataclass
class RSAStats:
    """
    Simple container for benchmark timings.
    """
    key_bits: int
    keygen_time: float
    encrypt_time: float
    decrypt_time: float
    sign_time: float
    verify_time: float



# Section 2: Utility Functions (Integers <-> Bytes, Pretty Hex)



def i2osp(x: int, length: int) -> bytes:
    """
    Integer-to-Octet-String primitive (I2OSP).

    Convert a non-negative integer x into a big-endian byte string of length 'length'.
    Raise ValueError if x is too large.
    """
    if x < 0 or x >= 256 ** length:
        raise ValueError("integer too large for requested length")
    return x.to_bytes(length, byteorder="big")


def os2ip(x: bytes) -> int:
    """
    Octet-String-to-Integer primitive (OS2IP).

    Convert a byte string into a non-negative integer.
    """
    return int.from_bytes(x, byteorder="big")


def pretty_hex(data: bytes, max_len: int = 32) -> str:
    """
    Return a hex string for bytes, optionally truncated for display.
    """
    if len(data) <= max_len:
        return data.hex()
    return data[:max_len].hex() + "..."



# Section 3: Primality Testing and Prime Generation



def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """
    Miller–Rabin probabilistic primality test.

    Returns True if n is probably prime, False if definitely composite.
    """
    if n < 2:
        return False

    # Quick checks against small primes to weed out easy composites
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    # Write n - 1 as 2^r * d with d odd (standard Miller–Rabin decomposition)
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Repeat the test with multiple random bases 'a'
    for _ in range(rounds):
        # a is chosen uniformly from [2, n-2]
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            # This round passes trivially
            continue

        # Square x up to r-1 times and see if we ever hit n-1
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            # None of the squarings produced n-1 => definitely composite
            return False

    # If we never found a contradiction, n is "probably prime"
    return True


def generate_prime(bits: int) -> int:
    """
    Generate a probable prime of the given bit length.
    """
    while True:
        # Generate a random number with the top bit set (so it has 'bits' bits)
        candidate = secrets.randbits(bits)

        # Force the highest bit to 1 and make it odd (LSB = 1)
        candidate |= (1 << (bits - 1)) | 1

        if is_probable_prime(candidate):
            return candidate



# Section 4: RSA Key Generation



def generate_rsa_keypair(config: RSAConfig) -> RSAKeyPair:
    """
    Generate an RSA keypair using the given config.

    Steps:
      - Generate two primes p, q of roughly half the target size
      - Compute n = p * q and phi = (p-1)*(q-1)
      - Ensure gcd(e, phi) == 1
      - Compute d = e^{-1} mod phi
    """
    bits = config.key_bits
    e = config.e

    # Split the target bit-size between p and q
    p_bits = bits // 2
    q_bits = bits - p_bits

    while True:
        p = generate_prime(p_bits)
        q = generate_prime(q_bits)

        # It's extremely unlikely, but check that p != q
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        # e must be coprime with φ(n)
        if math.gcd(e, phi) != 1:
            # In that (rare) case, just try again.
            continue

        # Compute d such that e*d ≡ 1 (mod φ(n))
        d = pow(e, -1, phi)

        public = PublicKey(n=n, e=e)
        private = PrivateKey(n=n, d=d)
        return RSAKeyPair(public=public, private=private)



# Section 5: OAEP Support (MGF1, encode, decode)



def mgf1(seed: bytes, length: int, hash_func: Callable[[], "hashlib._Hash"]) -> bytes:
    """
    MGF1: Mask Generation Function 1, used by OAEP.

    Given a seed and a desired length, repeatedly hashes
    seed || counter and concatenates the results.
    """
    hlen = hash_func().digest_size
    if length > (1 << 32) * hlen:
        raise ValueError("mask too long")

    T = b""
    # MGF1 iterates a counter, hashes seed || counter, and concatenates
    for counter in range(0, math.ceil(length / hlen)):
        C = counter.to_bytes(4, byteorder="big")
        T += hash_func(seed + C).digest()
    return T[:length]


def oaep_encode(
    message: bytes,
    k: int,
    label: bytes = b"",
    hash_func: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> bytes:
    """
    OAEP encode a message into an encoded message (EM) of length k bytes.
    """
    hlen = hash_func().digest_size
    mlen = len(message)

    # OAEP demands that the message fits into k with some space for hashes and padding
    if mlen > k - 2 * hlen - 2:
        raise ValueError("message too long for OAEP")

    # Compute lHash = Hash(label)
    lhash = hash_func(label).digest()

    # Construct the data block (DB) = lHash || PS || 0x01 || message
    # PS is all zero bytes and fills the remaining space.
    ps = b"\x00" * (k - mlen - 2 * hlen - 2)
    db = lhash + ps + b"\x01" + message

    # Generate a random seed
    seed = secrets.token_bytes(hlen)

    # Mask DB with a mask derived from the seed
    dbmask = mgf1(seed, k - hlen - 1, hash_func)
    masked_db = bytes(x ^ y for x, y in zip(db, dbmask))

    # Mask the seed using a mask derived from the masked DB
    seedmask = mgf1(masked_db, hlen, hash_func)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seedmask))

    # Final encoded message: EM = 0x00 || masked_seed || masked_db
    return b"\x00" + masked_seed + masked_db


def oaep_decode(
    em: bytes,
    label: bytes = b"",
    hash_func: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> bytes:
    """
    OAEP decode an encoded message (EM) back into a plaintext message.
    """
    hlen = hash_func().digest_size

    if len(em) < 2 * hlen + 2:
        raise ValueError("decryption error (OAEP: input too short)")

    if em[0] != 0:
        raise ValueError("decryption error (OAEP: first byte not 0x00)")

    masked_seed = em[1:1 + hlen]
    masked_db = em[1 + hlen:]

    # Reverse seedmask application
    seedmask = mgf1(masked_db, hlen, hash_func)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seedmask))

    # Reverse dbmask application
    dbmask = mgf1(seed, len(masked_db), hash_func)
    db = bytes(x ^ y for x, y in zip(masked_db, dbmask))

    # Split DB into lHash' || PS || 0x01 || M
    lhash = hash_func(label).digest()
    lhash_prime = db[:hlen]
    if lhash_prime != lhash:
        raise ValueError("decryption error (OAEP: label hash mismatch)")

    rest = db[hlen:]
    try:
        idx = rest.index(b"\x01")
    except ValueError:
        raise ValueError("decryption error (OAEP: 0x01 separator not found)")

    ps = rest[:idx]
    # All bytes in PS must be zero
    if any(b != 0 for b in ps):
        raise ValueError("decryption error (OAEP: non-zero padding)")

    message = rest[idx + 1:]
    return message



# Section 6: RSA Core (Encrypt/Decrypt + Sign/Verify)



def rsa_encrypt_oaep(
    message: bytes,
    pub: PublicKey,
    label: bytes = b"",
    hash_func: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> bytes:
    """
    Encrypt a message using RSA + OAEP.
    """
    k = pub.size_bytes
    em = oaep_encode(message, k, label, hash_func)
    m_int = os2ip(em)

    if m_int >= pub.n:
        raise ValueError("encoded message representative too large for modulus")

    c_int = pow(m_int, pub.e, pub.n)
    c = i2osp(c_int, k)
    return c


def rsa_decrypt_oaep(
    ciphertext: bytes,
    priv: PrivateKey,
    label: bytes = b"",
    hash_func: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> bytes:
    """
    Decrypt a ciphertext encrypted with RSA + OAEP and recover the original message.
    """
    k = priv.size_bytes
    if len(ciphertext) != k:
        raise ValueError("ciphertext length does not match key size")

    c_int = os2ip(ciphertext)
    if c_int >= priv.n:
        raise ValueError("ciphertext representative too large for modulus")

    m_int = pow(c_int, priv.d, priv.n)
    em = i2osp(m_int, k)
    message = oaep_decode(em, label, hash_func)
    return message


def rsa_sign_hash(
    message: bytes,
    priv: PrivateKey,
    hash_func: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> bytes:
    """
    Sign a message using a simple "hash-then-RSA" scheme.

    This is educational and does not implement a full standard signature format.
    """
    k = priv.size_bytes
    digest = hash_func(message).digest()
    m_int = os2ip(digest)

    if m_int >= priv.n:
        raise ValueError("hash value too large relative to modulus")

    s_int = pow(m_int, priv.d, priv.n)
    signature = i2osp(s_int, k)
    return signature


def rsa_verify_hash(
    message: bytes,
    signature: bytes,
    pub: PublicKey,
    hash_func: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> bool:
    """
    Verify a signature created by rsa_sign_hash.
    """
    if len(signature) != pub.size_bytes:
        # Signature should match the size of the modulus
        return False

    digest = hash_func(message).digest()
    m_int = os2ip(digest)
    s_int = os2ip(signature)

    v_int = pow(s_int, pub.e, pub.n)
    return v_int == m_int



# Section 7: Key Serialization (JSON + Base64)



def public_key_to_dict(pub: PublicKey) -> dict:
    """
    Serialize a PublicKey to a JSON-friendly dict.
    """
    return {
        "n": base64.b64encode(i2osp(pub.n, pub.size_bytes)).decode("utf-8"),
        "e": pub.e,
    }


def public_key_from_dict(data: dict) -> PublicKey:
    """
    Reconstruct a PublicKey from a dictionary produced by public_key_to_dict.
    """
    n_bytes = base64.b64decode(data["n"].encode("utf-8"))
    n = os2ip(n_bytes)
    e = int(data["e"])
    return PublicKey(n=n, e=e)


def private_key_to_dict(priv: PrivateKey) -> dict:
    """
    Serialize a PrivateKey to a JSON-friendly dict.

    Note: this stores only n and d, not the prime factors.
    """
    return {
        "n": base64.b64encode(i2osp(priv.n, priv.size_bytes)).decode("utf-8"),
        "d": base64.b64encode(i2osp(priv.d, priv.size_bytes)).decode("utf-8"),
    }


def private_key_from_dict(data: dict) -> PrivateKey:
    """
    Reconstruct a PrivateKey from a dictionary produced by private_key_to_dict.
    """
    n_bytes = base64.b64decode(data["n"].encode("utf-8"))
    d_bytes = base64.b64decode(data["d"].encode("utf-8"))
    n = os2ip(n_bytes)
    d = os2ip(d_bytes)
    return PrivateKey(n=n, d=d)


def save_keypair_to_file(pair: RSAKeyPair, path: str) -> None:
    """
    Save an RSAKeyPair to a JSON file.
    """
    data = {
        "public": public_key_to_dict(pair.public),
        "private": private_key_to_dict(pair.private),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_keypair_from_file(path: str) -> RSAKeyPair:
    """
    Load an RSAKeyPair from a JSON file created by save_keypair_to_file.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    pub = public_key_from_dict(data["public"])
    priv = private_key_from_dict(data["private"])
    return RSAKeyPair(public=pub, private=priv)



# Section 8: Test Suite



def test_miller_rabin_small_values() -> None:
    """
    Sanity-check that the primality test behaves on small known values.
    """
    primes = [2, 3, 5, 11, 23, 97, 101]
    composites = [1, 4, 6, 9, 21, 25, 100]

    for p in primes:
        assert is_probable_prime(p), f"Expected prime: {p}"
    for c in composites:
        assert not is_probable_prime(c), f"Expected composite: {c}"


def test_keygen_and_encrypt_decrypt() -> None:
    """
    Generate a small key and verify encryption/decryption works.
    """
    cfg = RSAConfig(key_bits=1024)
    pair = generate_rsa_keypair(cfg)
    msg = b"Test message for RSA OAEP"
    c = rsa_encrypt_oaep(msg, pair.public, hash_func=cfg.hash_func)
    decrypted = rsa_decrypt_oaep(c, pair.private, hash_func=cfg.hash_func)
    assert decrypted == msg, "Decrypt did not recover original message"


def test_sign_verify() -> None:
    """
    Verify that signatures produced by rsa_sign_hash can be verified.
    """
    cfg = RSAConfig(key_bits=1024)
    pair = generate_rsa_keypair(cfg)
    message = b"Signing test message"
    sig = rsa_sign_hash(message, pair.private, hash_func=cfg.hash_func)
    ok = rsa_verify_hash(message, sig, pair.public, hash_func=cfg.hash_func)
    assert ok, "Signature verification failed"


def test_oaep_roundtrip() -> None:
    """
    Test OAEP encode/decode round-trip without RSA.
    """
    hash_func = hashlib.sha256
    k = 128  # simulate 1024-bit RSA (128 bytes)
    msg = b"Short OAEP test"
    em = oaep_encode(msg, k, b"label", hash_func)
    recovered = oaep_decode(em, b"label", hash_func)
    assert recovered == msg, "OAEP decode did not recover message"


def run_all_tests() -> None:
    """
    Run all internal tests. Raise AssertionError on failure.
    """
    print("[*] Running internal test suite...")
    test_miller_rabin_small_values()
    print("  - Miller–Rabin small values: OK")
    test_oaep_roundtrip()
    print("  - OAEP roundtrip: OK")
    test_keygen_and_encrypt_decrypt()
    print("  - RSA keygen + encrypt/decrypt: OK")
    test_sign_verify()
    print("  - RSA sign/verify: OK")
    print("[+] All tests passed.\n")



# Section 9: Simple Benchmark



def benchmark_rsa(config: RSAConfig) -> RSAStats:
    """
    Benchmark basic RSA operations for the given configuration.
    """
    hash_func = config.hash_func
    msg = b"Benchmark message for RSA operations"

    # Key generation timing
    t0 = time.perf_counter()
    pair = generate_rsa_keypair(config)
    t1 = time.perf_counter()

    # Encryption timing
    t2 = time.perf_counter()
    c = rsa_encrypt_oaep(msg, pair.public, hash_func=hash_func)
    t3 = time.perf_counter()

    # Decryption timing
    t4 = time.perf_counter()
    m2 = rsa_decrypt_oaep(c, pair.private, hash_func=hash_func)
    t5 = time.perf_counter()

    # Signing timing
    t6 = time.perf_counter()
    sig = rsa_sign_hash(msg, pair.private, hash_func=hash_func)
    t7 = time.perf_counter()

    # Verification timing
    t8 = time.perf_counter()
    ok = rsa_verify_hash(msg, sig, pair.public, hash_func=hash_func)
    t9 = time.perf_counter()

    # Sanity checks: the benchmark should still be *functionally* correct
    assert m2 == msg, "Benchmark decrypt mismatch"
    assert ok, "Benchmark verify failed"

    stats = RSAStats(
        key_bits=config.key_bits,
        keygen_time=t1 - t0,
        encrypt_time=t3 - t2,
        decrypt_time=t5 - t4,
        sign_time=t7 - t6,
        verify_time=t9 - t8,
    )
    return stats


def print_benchmark(stats: RSAStats) -> None:
    """
    Print benchmark results.
    """
    print(f"[*] RSA {stats.key_bits}-bit benchmark results:")
    print(f"  Key generation: {stats.keygen_time:.4f} s")
    print(f"  Encryption:     {stats.encrypt_time:.6f} s")
    print(f"  Decryption:     {stats.decrypt_time:.6f} s")
    print(f"  Signing:        {stats.sign_time:.6f} s")
    print(f"  Verification:   {stats.verify_time:.6f} s")
    print()



# Section 10: Interactive CLI


class RSACLI:
    """
    A small interactive command-line interface to exercise this RSA module.

    This is meant as a learning tool so you can play with RSA directly
    from the terminal without writing your own scripts.
    """

    def __init__(self) -> None:
        # Start with a default configuration
        self.config = RSAConfig()
        # Keypair will be None until we generate or load one
        self.keypair: Optional[RSAKeyPair] = None

    def ensure_keys(self) -> None:
        """
        Ensure that we have a keypair ready before doing crypto operations.

        If no keypair is currently loaded, this will automatically generate one.
        """
        if self.keypair is None:
            print("[!] No keypair loaded. Generating a new one...")
            self.keypair = generate_rsa_keypair(self.config)
            print("[+] Keypair generated.\n")

    # ----- Menu Operations -----

    def op_generate_keys(self) -> None:
        """
        Generate a new RSA keypair based on the current config.
        """
        print(f"[*] Generating RSA keypair ({self.config.key_bits} bits, e={self.config.e})...")
        self.keypair = generate_rsa_keypair(self.config)
        print("[+] Generated new keypair.\n")

    def op_save_keys(self) -> None:
        """
        Save the current keypair to a JSON file.
        """
        if self.keypair is None:
            print("[!] No keypair to save. Generate or load one first.\n")
            return
        path = input("Enter filename to save keys (e.g., keys.json): ").strip()
        if not path:
            print("[!] Empty filename. Aborting.\n")
            return
        save_keypair_to_file(self.keypair, path)
        print(f"[+] Keys saved to {path}\n")

    def op_load_keys(self) -> None:
        """
        Load a keypair from a JSON file.
        """
        path = input("Enter filename to load keys from: ").strip()
        if not path:
            print("[!] Empty filename. Aborting.\n")
            return
        try:
            self.keypair = load_keypair_from_file(path)
            print(f"[+] Keys loaded from {path}\n")
        except Exception as e:
            print(f"[!] Failed to load keys: {e}\n")

    def op_encrypt_message(self) -> None:
        """
        Prompt the user for a plaintext message and encrypt it.
        """
        self.ensure_keys()
        assert self.keypair is not None
        text = input("Enter plaintext message to encrypt: ")
        msg = text.encode("utf-8")
        pub = self.keypair.public
        label = b""
        hash_func = self.config.hash_func
        try:
            ciphertext = rsa_encrypt_oaep(msg, pub, label, hash_func)
            enc = RSAEncryptedMessage(ciphertext, label)
            print("Ciphertext (Base64):")
            print(enc.to_base64())
            print()
        except Exception as e:
            print(f"[!] Encryption failed: {e}\n")

    def op_decrypt_message(self) -> None:
        """
        Prompt for a Base64 ciphertext and decrypt it.
        """
        self.ensure_keys()
        assert self.keypair is not None
        b64 = input("Enter Base64 ciphertext to decrypt: ").strip()
        try:
            enc = RSAEncryptedMessage.from_base64(b64)
            priv = self.keypair.private
            hash_func = self.config.hash_func
            msg = rsa_decrypt_oaep(enc.ciphertext, priv, enc.label, hash_func)
            print("Recovered plaintext:")
            print(msg.decode("utf-8", errors="replace"))
            print()
        except Exception as e:
            print(f"[!] Decryption failed: {e}\n")

    def op_sign_message(self) -> None:
        """
        Sign a message entered by the user.
        """
        self.ensure_keys()
        assert self.keypair is not None
        text = input("Enter message to sign: ")
        msg = text.encode("utf-8")
        priv = self.keypair.private
        hash_func = self.config.hash_func
        try:
            sig_bytes = rsa_sign_hash(msg, priv, hash_func)
            sig = RSASignature(sig_bytes)
            print("Signature (Base64):")
            print(sig.to_base64())
            print()
        except Exception as e:
            print(f"[!] Signing failed: {e}\n")

    def op_verify_message(self) -> None:
        """
        Verify a signature for a user-provided message.
        """
        self.ensure_keys()
        assert self.keypair is not None
        text = input("Enter message to verify: ")
        msg = text.encode("utf-8")
        b64_sig = input("Enter Base64 signature: ").strip()
        pub = self.keypair.public
        hash_func = self.config.hash_func

        try:
            sig = RSASignature.from_base64(b64_sig)
            ok = rsa_verify_hash(msg, sig.signature, pub, hash_func)
            print(f"Signature valid? {ok}\n")
        except Exception as e:
            print(f"[!] Verification failed: {e}\n")

    def op_run_tests(self) -> None:
        """
        Run the internal test suite.
        """
        try:
            run_all_tests()
        except AssertionError as e:
            print(f"[!] Test failure: {e}\n")

    def op_run_benchmark(self) -> None:
        """
        Run a simple benchmark for the current configuration.

        You can optionally change the key size before the benchmark runs.
        """
        bits_str = input(f"Enter key size in bits (default {self.config.key_bits}): ").strip()
        if bits_str:
            try:
                self.config.key_bits = int(bits_str)
            except ValueError:
                print("[!] Invalid key size. Using previous setting.\n")
        print("[*] Running benchmark...")
        stats = benchmark_rsa(self.config)
        print_benchmark(stats)

    def op_show_config(self) -> None:
        """
        Show the current RSA configuration.
        """
        print("Current RSA configuration:")
        print(f"  key_bits = {self.config.key_bits}")
        print(f"  e        = {self.config.e}")
        print(f"  hash     = {self.config.hash_name}")
        print()

    # ----- Main Loop -----

    def run(self) -> None:
        """
        Main CLI loop: display a menu and dispatch to the selected operation.
        """
        MENU = """
RSA Project – Menu
==================

1) Generate new keypair
2) Save current keypair to file
3) Load keypair from file
4) Encrypt a message (OAEP)
5) Decrypt a message (OAEP)
6) Sign a message (hash-then-RSA)
7) Verify a signature
8) Run internal tests
9) Run benchmark
10) Show current configuration
0) Quit
"""

        while True:
            print(MENU)
            choice = input("Select an option: ").strip()

            if choice == "1":
                self.op_generate_keys()
            elif choice == "2":
                self.op_save_keys()
            elif choice == "3":
                self.op_load_keys()
            elif choice == "4":
                self.op_encrypt_message()
            elif choice == "5":
                self.op_decrypt_message()
            elif choice == "6":
                self.op_sign_message()
            elif choice == "7":
                self.op_verify_message()
            elif choice == "8":
                self.op_run_tests()
            elif choice == "9":
                self.op_run_benchmark()
            elif choice == "10":
                self.op_show_config()
            elif choice == "0":
                print("Goodbye.")
                break
            else:
                print("[!] Invalid choice. Please try again.\n")



# Section 11: Main Entry Point


if __name__ == "__main__":
    # If you want, uncomment this to always run tests on startup:
    # run_all_tests()

    cli = RSACLI()
    cli.run()



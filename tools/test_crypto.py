"""
Crypto Challenge Service - Simulated A/D CTF Encryption Service
Contains classic cryptographic pitfalls: ECB leak, predictable IV, weak RSA, and broken hashes.
"""

import time
import random
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA

# [Lỗ hổng 1]: Broken Hash Algorithm (CWE-328)
def generate_user_token(username: str) -> str:
    # MD5 is broken and vulnerable to collisions / rainbow tables
    token = hashlib.md5(username.encode()).hexdigest()
    return token

# [Lỗ hổng 2]: Predictable PRNG Seed (CWE-338)
def generate_otp() -> int:
    # Seeding with system timestamp enables brute-force reconstruction of OTP sequence
    random.seed(int(time.time()))
    return random.randint(100000, 999999)

# [Lỗ hổng 3]: Insecure Cipher Mode AES-ECB (CWE-327)
def encrypt_profile_ecb(data: bytes, key: bytes) -> bytes:
    # ECB does not use an IV; identical blocks yield identical ciphertexts
    cipher = AES.new(key, AES.MODE_ECB)
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len]) * pad_len
    return cipher.encrypt(padded)

# [Lỗ hổng 4]: Static / Predictable IV (CWE-329)
def encrypt_flag_cbc(flag: bytes, key: bytes) -> bytes:
    # Static zero-filled IV allows XOR differential cryptanalysis
    iv = b"0000000000000000"
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(flag)

# [Lỗ hổng 5]: Weak RSA Key Size (CWE-326)
def generate_service_keypair():
    # 1024-bit RSA is vulnerable to factorization via CADO-NFS / ECM
    key = RSA.generate(1024)
    return key

# [Lỗ hổng 6]: Legacy Broken Cipher (CWE-327)
def legacy_encrypt(msg: bytes, key: bytes) -> bytes:
    # DES uses a short 56-bit key easily brute-forced
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(msg)

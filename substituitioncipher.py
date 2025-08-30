#!/usr/bin/env python3
# cli_cipher_hex.py
# Byte-wise substitution cipher (toy). Prints hex; reads hex. No files.

import sys, hashlib, getpass, os

SALT_LEN = 16
CHECK_LEN = 8

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=32)

def make_perm(key: bytes) -> bytes:
    # Fisher–Yates with deterministic RNG from BLAKE2s(key||counter)
    perm = list(range(256))
    ctr = 0
    for i in range(255, 0, -1):
        r = int.from_bytes(hashlib.blake2s(key + ctr.to_bytes(8, "big")).digest()[:4], "big")
        j = r % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
        ctr += 1
    return bytes(perm)

def invert_perm(perm: bytes) -> bytes:
    inv = [0]*256
    for i, v in enumerate(perm):
        inv[v] = i
    return bytes(inv)

def encrypt_text_to_bytes(text: str, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    key  = derive_key(password, salt)
    enc_table = make_perm(key)
    check = hashlib.blake2s(b"check"+key, digest_size=CHECK_LEN).digest()
    body = text.encode("utf-8").translate(enc_table)
    return salt + check + body  # headerless: SALT | CHECK | BODY

def decrypt_bytes_to_text(blob: bytes, password: str) -> str:
    if len(blob) < SALT_LEN + CHECK_LEN:
        raise ValueError("Ciphertext too short")
    salt = blob[:SALT_LEN]
    check_stored = blob[SALT_LEN:SALT_LEN+CHECK_LEN]
    body = blob[SALT_LEN+CHECK_LEN:]
    key = derive_key(password, salt)
    check_calc = hashlib.blake2s(b"check"+key, digest_size=CHECK_LEN).digest()
    if check_stored != check_calc:
        raise ValueError("Wrong password or corrupted data")
    dec_table = invert_perm(make_perm(key))
    return body.translate(dec_table).decode("utf-8")

def usage():
    print("Usage:")
    print("  Encrypt: python3 cli_cipher_hex.py enc \"your phrase\"")
    print("  Decrypt: python3 cli_cipher_hex.py dec <hex_string>")
    print("\nNotes:")
    print("  - Output is hex for safe copy/paste.")
    print("  - Input for dec must be the hex produced by enc.")
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("enc", "dec"):
        usage()

    mode = sys.argv[1]
    arg  = sys.argv[2]
    password = getpass.getpass("Password: ")

    try:
        if mode == "enc":
            ct = encrypt_text_to_bytes(arg, password)
            print(ct.hex())
        else:  # dec
            blob = bytes.fromhex(arg.strip())
            pt = decrypt_bytes_to_text(blob, password)
            print(pt)
    except Exception as e:
        print("Error:", e)
        sys.exit(2)


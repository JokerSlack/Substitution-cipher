#!/usr/bin/env python3
"""
Keyed byte-wise substitution cipher (toy, supports *all* characters).

- Works on bytes 0..255 (so any text encoding or binary file).
- Deterministic mapping is derived from a password via PBKDF2 and a random salt.
- Adds a short keyed check to detect wrong password/corruption.

⚠️ Security note: Substitution ciphers are *not* secure against modern cryptanalysis.
Use only for learning or obfuscation. For real security, use libs like `cryptography`
(AES-GCM/ChaCha20-Poly1305).
"""
import os, sys, argparse, hashlib, getpass

MAGIC = b"SUBSTC1\0"   # header tag to recognize this format
SALT_LEN = 16
CHECK_LEN = 8

def derive_key(password: str, salt: bytes, iterations: int = 200_000, dklen: int = 32) -> bytes:
    """PBKDF2-HMAC-SHA256 derivation."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=dklen)

def make_perm(key: bytes) -> bytes:
    """
    Make a deterministic permutation of 0..255 using Fisher–Yates.
    Randomness is produced by BLAKE2s(key || counter).
    """
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

def make_tables(password: str, salt: bytes):
    key = derive_key(password, salt)
    perm = make_perm(key)
    enc_table = perm
    dec_table = invert_perm(perm)
    # Short keyed check to detect wrong password/corruption
    check = hashlib.blake2s(b"check"+key, digest_size=CHECK_LEN).digest()
    return enc_table, dec_table, check

def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    enc_table, _, check = make_tables(password, salt)
    body = data.translate(enc_table)
    return MAGIC + salt + check + body

def decrypt_bytes(data: bytes, password: str) -> bytes:
    if not data.startswith(MAGIC) or len(data) < len(MAGIC)+SALT_LEN+CHECK_LEN:
        raise ValueError("Invalid data or missing header")
    salt_off = len(MAGIC)
    check_off = salt_off + SALT_LEN
    body_off  = check_off + CHECK_LEN
    salt = data[salt_off:check_off]
    check_stored = data[check_off:body_off]
    _, dec_table, check_calc = make_tables(password, salt)
    if check_stored != check_calc:
        raise ValueError("Wrong password or corrupted data (check failed)")
    body = data[body_off:]
    return body.translate(dec_table)

def read_all(path: str) -> bytes:
    if path == "-" or path == "":
        return sys.stdin.buffer.read()
    with open(path, "rb") as f:
        return f.read()

def write_all(path: str, data: bytes):
    if path == "-" or path == "":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        with open(path, "wb") as f:
            f.write(data)

def main():
    p = argparse.ArgumentParser(description="Keyed substitution cipher over all bytes (toy).")
    p.add_argument("mode", choices=["enc","dec"], help="enc=encrypt, dec=decrypt")
    p.add_argument("-i","--infile", default="-", help="input file (default: stdin)")
    p.add_argument("-o","--outfile", default="-", help="output file (default: stdout)")
    p.add_argument("-p","--password", help="password (omit to prompt securely)")
    args = p.parse_args()

    password = args.password or getpass.getpass("Password: ")
    data = read_all(args.infile)

    try:
        if args.mode == "enc":
            out = encrypt_bytes(data, password)
        else:
            out = decrypt_bytes(data, password)
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(2)

    write_all(args.outfile, out)

if __name__ == "__main__":
    main()

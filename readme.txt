===================================================
 Substitution Cipher (CLI-Only, Hex Output)
===================================================

This program is a toy substitution cipher written in Python.
It encrypts and decrypts arbitrary phrases directly from the
command line without using files.

Encryption works on all characters (letters, numbers, symbols,
emoji, etc.) by substituting every byte (0–255). The program
prints results as hex strings so you can easily copy/paste
ciphertext in the terminal.

⚠️ SECURITY NOTE
----------------
This is an educational cipher, not secure for real-world use.
A determined attacker can break substitution ciphers.
If you need real cryptographic security, use AES-GCM or
ChaCha20-Poly1305 from the `cryptography` library.

---------------------------------------------------
 Requirements
---------------------------------------------------
- Python 3.8 or newer
- No external libraries required

---------------------------------------------------
 Usage
---------------------------------------------------

Encrypt a phrase (prints hex string):
    python3 cli_cipher_hex.py enc "Knowledge is power 😎🔥"
    Password: mypassword

Output example:
    7a37ef3bc3c91af9... (hex string)

Decrypt the hex string back to plaintext:
    python3 cli_cipher_hex.py dec 7a37ef3bc3c91af9...
    Password: mypassword

Output:
    Knowledge is power 😎🔥

---------------------------------------------------
 Program Flow
---------------------------------------------------
1. You provide a password (the secret key).
2. A random 16-byte salt is generated.
3. A substitution mapping (permutation of 0–255) is derived
   from the password + salt using PBKDF2-HMAC-SHA256.
4. Data is translated using that mapping.
5. Output format:
       [SALT (16 bytes)][CHECK (8 bytes)][CIPHERTEXT BODY]

- SALT ensures different ciphertext every time.
- CHECK (8 bytes) detects wrong password/corruption.
- CIPHERTEXT BODY is the substituted text.

---------------------------------------------------
 Examples
---------------------------------------------------
Encrypt:
    $ python3 cli_cipher_hex.py enc "Olá mundo!"
    Password: secret
    1234abcd5678...

Decrypt:
    $ python3 cli_cipher_hex.py dec 1234abcd5678...
    Password: secret
    Olá mundo!

---------------------------------------------------
 License
---------------------------------------------------
MIT License

Copyright (c) 2025 jokerSlack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


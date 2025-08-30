===================================================
 Substitution Cipher (Toy Implementation in Python)
===================================================

This is a simple byte-wise substitution cipher written in Python.
It works on ALL characters and binary data (letters, numbers,
punctuation, emoji, files, etc.), not just alphabetic text.

⚠️ SECURITY NOTE
----------------
This substitution cipher is for EDUCATIONAL or obfuscation use only.
It is NOT cryptographically secure against modern attacks.
For real security, use AES-GCM or ChaCha20-Poly1305 from the
`cryptography` library.

---------------------------------------------------
 Requirements
---------------------------------------------------
- Python 3.8 or newer
- No third-party dependencies

(Optional for real security):
    cryptography>=42.0.0

---------------------------------------------------
 Usage (Command-Line)
---------------------------------------------------

Encrypt a text file:
    python3 subst.py enc -i message.txt -o secret.bin -p "your_password"

Decrypt a file:
    python3 subst.py dec -i secret.bin -o recovered.txt -p "your_password"

Use stdin/stdout (streams):
    echo "Hello 😎 123 !" | python3 subst.py enc -p pass > out.bin
    python3 subst.py dec -p pass < out.bin

---------------------------------------------------
 Command-Line Options
---------------------------------------------------
  mode            enc = encrypt, dec = decrypt
  -i, --infile    Input file (default: stdin)
  -o, --outfile   Output file (default: stdout)
  -p, --password  Password (omit to be prompted securely)

---------------------------------------------------
 Programmatic Usage
---------------------------------------------------
You can also import and use the functions directly in Python:

    from subst import encrypt_bytes, decrypt_bytes

    # Encrypt a string
    secret = encrypt_bytes("Olá, mundo! 😎".encode("utf-8"), "superpass")

    # Save secret to a file
    with open("secret.bin", "wb") as f:
        f.write(secret)

    # Later, decrypt it back
    with open("secret.bin", "rb") as f:
        data = f.read()
    plain = decrypt_bytes(data, "superpass").decode("utf-8")

    print("Decrypted text:", plain)

---------------------------------------------------
 File Format
---------------------------------------------------
The encrypted file has the following structure:

    [MAGIC HEADER][SALT][CHECK BYTES][ENCRYPTED BODY]

- MAGIC HEADER:   identifies the format ("SUBSTC1\0")
- SALT:           random 16-byte salt per encryption
- CHECK BYTES:    8-byte keyed hash to detect wrong password
- BODY:           data encrypted via substitution mapping

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

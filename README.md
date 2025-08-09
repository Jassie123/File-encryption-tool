import argparse
import base64
import getpass
import os
import sys
from typing import Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    print("Missing dependency: please install cryptography (pip install cryptography)")
    raise

# Constants for file format
MAGIC = b"LTEN"  # 4 bytes magic header
VERSION = b"\x01"  # 1 byte version
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERS = 200_000  # PBKDF2 iterations


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte key from password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
        backend=default_backend(),
    )
    return kdf.derive(password)


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Encrypt plaintext with password; returns bytes in custom format."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    # format: MAGIC|VERSION|salt|nonce|ciphertext
    return MAGIC + VERSION + salt + nonce + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Decrypt blob produced by encrypt_bytes. Raises ValueError on auth failure."""
    if len(blob) < (len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE + 1):
        raise ValueError("Ciphertext too short or corrupted")
    if not blob.startswith(MAGIC):
        raise ValueError("Bad file format (magic mismatch)")
    pos = len(MAGIC)
    ver = blob[pos:pos+1]
    pos += 1
    if ver != VERSION:
        raise ValueError(f"Unsupported version: {ver}")
    salt = blob[pos:pos+SALT_SIZE]
    pos += SALT_SIZE
    nonce = blob[pos:pos+NONCE_SIZE]
    pos += NONCE_SIZE
    ciphertext = blob[pos:]
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_file(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def prompt_password(confirm: bool = False) -> str:
    p1 = getpass.getpass("Password: ")
    if confirm:
        p2 = getpass.getpass("Confirm password: ")
        if p1 != p2:
            raise ValueError("Passwords do not match")
    return p1


def parse_args():
    p = argparse.ArgumentParser(description="Lightweight file/text encryptor (AES-256-GCM)")
    sub = p.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a file or text")
    enc.add_argument("-i", "--infile", help="Input file path (binary). If omitted, use --text")
    enc.add_argument("-o", "--outfile", help="Output file path. If omitted with a file input, .enc is appended")
    enc.add_argument("--text", help="Encrypt the provided string instead of a file")
    enc.add_argument("--confirm", action="store_true", help="Confirm password input")

    dec = sub.add_parser("decrypt", help="Decrypt a file or text")
    dec.add_argument("-i", "--infile", help="Input file path (encrypted). If omitted, use --text")
    dec.add_argument("-o", "--outfile", help="Output file path. If omitted and input is file, .dec is used")
    dec.add_argument("--text", help="Base64 string to decrypt instead of a file")

    return p.parse_args()


def main():
    args = parse_args()
    try:
        if args.cmd == "encrypt":
            pwd = prompt_password(confirm=args.confirm)
            if args.text is not None:
                plaintext = args.text.encode("utf-8")
                blob = encrypt_bytes(plaintext, pwd)
                print(base64.b64encode(blob).decode("ascii"))
                return
            if not args.infile:
                print("--infile or --text required for encrypt", file=sys.stderr)
                sys.exit(2)
            data = read_file(args.infile)
            out = encrypt_bytes(data, pwd)
            outpath = args.outfile if args.outfile else args.infile + ".enc"
            write_file(outpath, out)
            print(f"Encrypted -> {outpath}")

        elif args.cmd == "decrypt":
            if args.text is not None:
                b = base64.b64decode(args.text)
                pwd = getpass.getpass("Password: ")
                plain = decrypt_bytes(b, pwd)
                try:
                    print(plain.decode("utf-8"))
                except UnicodeDecodeError:
                    # binary; show base64
                    print(base64.b64encode(plain).decode("ascii"))
                return
            if not args.infile:
                print("--infile or --text required for decrypt", file=sys.stderr)
                sys.exit(2)
            data = read_file(args.infile)
            pwd = getpass.getpass("Password: ")
            try:
                plain = decrypt_bytes(data, pwd)
            except Exception as e:
                print(f"Decryption failed: {e}", file=sys.stderr)
                sys.exit(1)
            outpath = args.outfile if args.outfile else args.infile + ".dec"
            write_file(outpath, plain)
            print(f"Decrypted -> {outpath}")

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from getpass import getpass

TOKEN_FILE = "token.txt"
OUTPUT_FILE = "token.enc"

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def main():
    if not os.path.exists(TOKEN_FILE):
        print("token.txt не найден")
        return

    password = getpass("Придумайте пароль для шифрования токена: ")

    with open(TOKEN_FILE, "r", encoding="utf-8") as f:
        token = f.read().strip().encode()

    salt = os.urandom(16)
    key = derive_key(password, salt)

    encrypted = Fernet(key).encrypt(token)

    with open(OUTPUT_FILE, "wb") as f:
        f.write(salt + encrypted)

    print("✅ token.enc создан")
    print("⚠ Удалите token.txt вручную!")

if __name__ == "__main__":
    main()

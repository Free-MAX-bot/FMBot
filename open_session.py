import os
import json
import base64
import getpass
from pathlib import Path
from playwright.sync_api import sync_playwright
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

SESSIONS_DIR = "sessions"


# ==============================
# Генерация ключа из пароля
# ==============================

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# ==============================
# Основная логика
# ==============================

def main():
    session_name = input("Введите кодовое имя сессии: ").strip()
    password = getpass.getpass("Введите пароль: ")

    enc_path = Path(SESSIONS_DIR) / f"{session_name}.enc"

    if not enc_path.exists():
        print("❌ Сессия не найдена")
        return

    # ==========================
    # Чтение файла
    # ==========================

    with open(enc_path, "rb") as f:
        file_data = f.read()

    if len(file_data) < 17:
        print("❌ Файл повреждён")
        return

    salt = file_data[:16]
    encrypted_data = file_data[16:]

    # ==========================
    # Расшифровка
    # ==========================

    try:
        key = derive_key(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data)
    except InvalidToken:
        print("❌ Неверный пароль или повреждён файл")
        return

    # ==========================
    # Преобразование JSON → dict
    # ==========================

    try:
        storage_dict = json.loads(decrypted.decode())
    except json.JSONDecodeError:
        print("❌ Ошибка чтения JSON (файл повреждён)")
        return

    # ==========================
    # Запуск Playwright
    # ==========================

    with sync_playwright() as p:
        browser = p.firefox.launch(headless=False)

        context = browser.new_context(
            storage_state=storage_dict
        )

        page = context.new_page()
        page.goto("https://web.max.ru/")

        input("Сессия открыта. Нажмите Enter для выхода.")
        browser.close()


if __name__ == "__main__":
    main()


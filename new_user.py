import os
import json
import base64
import getpass
from pathlib import Path
from playwright.sync_api import sync_playwright
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# =========================
# Константы
# =========================

SESSIONS_DIR = "sessions"
MAP_FILE = "session_map.json"
CHATS_FILE = "chats.json"
PERMISSIONS_FILE = "permissions.json"
WHITELIST_FILE = "white-list.txt"

os.makedirs(SESSIONS_DIR, exist_ok=True)

# =========================
# JSON утилиты
# =========================

def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


# =========================
# Session map
# =========================

def load_map():
    return load_json(MAP_FILE)


def save_map(data):
    save_json(MAP_FILE, data)


# =========================
# Whitelist
# =========================

def add_to_whitelist(user_id: str):
    existing = set()

    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            existing = set(line.strip() for line in f if line.strip())

    if user_id not in existing:
        with open(WHITELIST_FILE, "a", encoding="utf-8") as f:
            f.write(user_id + "\n")


# =========================
# Crypto
# =========================

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# =========================
# MAIN
# =========================

def main():
    print("=== Регистрация нового пользователя ===\n")

    session_map = load_map()

    user_id = input("Введите Telegram user_id: ").strip()
    if not user_id.isdigit():
        print("❌ Некорректный user_id")
        return

    if user_id in session_map:
        print("❌ У этого user_id уже есть сессия")
        return

    session_name = input("Введите кодовое имя сессии: ").strip()
    if not session_name:
        print("❌ Имя не может быть пустым")
        return

    enc_path = Path(SESSIONS_DIR) / f"{session_name}.enc"
    if enc_path.exists():
        print("❌ Сессия с таким именем уже существует")
        return

    password = getpass.getpass("Введите пароль для шифрования: ")

    temp_json = Path(SESSIONS_DIR) / f"{session_name}.json"

    # ======================
    # Открытие браузера
    # ======================

    with sync_playwright() as p:
        browser = p.firefox.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        page.goto("https://web.max.ru/")

        print("\nВ появившемся окне зарегистрируйтесь или войдите в аккаунт.")
        print("После входа нажмите Enter здесь...")
        input()

        # ======================
        # Добавление чатов
        # ======================

        chats = load_json(CHATS_FILE)
        permissions = load_json(PERMISSIONS_FILE)

        user_allowed = []

        print("\n=== Добавление чатов ===")

        while True:
            print("\nКак хотите назвать чат?")
            chat_name = input("Название (или 0 для завершения): ").strip()

            if chat_name == "0":
                break

            if not chat_name:
                print("❌ Название не может быть пустым.")
                continue

            print("\nЗайдите в нужный чат, скопируйте ссылку и вставьте сюда.")
            chat_url = input("Ссылка: ").strip()

            if not chat_url.startswith("https://web.max.ru/"):
                print("❌ Неверная ссылка.")
                continue

            # уникальный ключ
            chat_key = f"{session_name}_{len(chats) + 1}"

            chats[chat_key] = {
                "name": chat_name,
                "url": chat_url
            }

            user_allowed.append(chat_key)

            print(f"✅ Чат '{chat_name}' добавлен.")

        if not user_allowed:
            print("❌ Нужно добавить хотя бы один чат.")
            browser.close()
            return

        # сохраняем данные
        save_json(CHATS_FILE, chats)
        permissions[user_id] = user_allowed
        save_json(PERMISSIONS_FILE, permissions)

        # сохраняем storage
        context.storage_state(path=str(temp_json))
        browser.close()

    # ======================
    # Шифрование
    # ======================

    with open(temp_json, "rb") as f:
        data = f.read()

    salt = os.urandom(16)
    key = derive_key(password, salt)
    encrypted = Fernet(key).encrypt(data)

    with open(enc_path, "wb") as f:
        f.write(salt + encrypted)

    os.remove(temp_json)

    # ======================
    # Обновление map
    # ======================

    session_map[user_id] = session_name
    save_map(session_map)

    # ======================
    # Whitelist
    # ======================

    add_to_whitelist(user_id)

    print("\n==============================")
    print("✅ Пользователь успешно создан")
    print("✅ Сессия сохранена")
    print("✅ Чаты добавлены")
    print("✅ Права назначены")
    print("✅ user_id добавлен в white-list.txt")
    print("==============================\n")


if __name__ == "__main__":
    main()


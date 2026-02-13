import os
import json
import base64
import telebot
import threading
import queue
from pathlib import Path
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
from playwright.sync_api import sync_playwright
from getpass import getpass

# =========================
# Константы
# =========================

SESSIONS_DIR = "sessions"
MAP_FILE = "session_map.json"
CHATS_FILE = "chats.json"
PERMISSIONS_FILE = "permissions.json"

ACTIVE_BROWSERS = {}
USER_UI_MESSAGE = {}
PENDING_MESSAGES = {}

os.makedirs(SESSIONS_DIR, exist_ok=True)

# =========================
# Утилиты
# =========================

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_whitelist():
    if not os.path.exists("white-list.txt"):
        return set()
    with open("white-list.txt", "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())


def load_encrypted_token():
    if not os.path.exists("token.enc"):
        print("token.enc не найден")
        exit(1)

    password = getpass("Введите пароль для запуска бота: ")

    with open("token.enc", "rb") as f:
        file_data = f.read()

    salt = file_data[:16]
    encrypted_data = file_data[16:]

    try:
        key = derive_key(password, salt)
        decrypted = Fernet(key).decrypt(encrypted_data)
        return decrypted.decode().strip()
    except InvalidToken:
        print("❌ Неверный пароль.")
        exit(1)


TOKEN = load_encrypted_token()
WHITELIST = load_whitelist()

bot = telebot.TeleBot(TOKEN)

# =========================
# Session helpers
# =========================

def has_session(user_id):
    session_map = load_json(MAP_FILE)
    return str(user_id) in session_map


def get_session_name(user_id):
    session_map = load_json(MAP_FILE)
    return session_map.get(str(user_id))


def is_authorized(user_id):
    return str(user_id) in WHITELIST


def edit_ui(user_id, chat_id, text, markup):
    if user_id in USER_UI_MESSAGE:
        try:
            bot.edit_message_text(
                text,
                chat_id,
                USER_UI_MESSAGE[user_id],
                reply_markup=markup
            )
            return
        except:
            pass

    msg = bot.send_message(chat_id, text, reply_markup=markup)
    USER_UI_MESSAGE[user_id] = msg.message_id

# =========================
# Playwright Worker
# =========================

def browser_worker(user_id, storage_state, command_queue):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(storage_state=storage_state)
        page = context.new_page()
        page.goto("https://web.max.ru/")

        while True:
            try:
                cmd = command_queue.get(timeout=3600)
            except:
                break

            if cmd["type"] == "send_message":
                try:
                    page.goto(cmd["url"])
                    editor = page.locator('div[data-lexical-editor="true"]')
                    editor.wait_for(timeout=15000)
                    editor.click()
                    page.keyboard.type(cmd["text"], delay=30)
                    page.locator(
                        'button[aria-label="Отправить сообщение"]'
                    ).click()
                except Exception as e:
                    print("Send error:", e)

            elif cmd["type"] == "close":
                break

        browser.close()

# =========================
# UI
# =========================

def show_login(user_id, chat_id):
    markup = InlineKeyboardMarkup()

    if has_session(user_id):
        markup.add(
            InlineKeyboardButton("🔐 Войти в сессию", callback_data="enter_password")
        )
        markup.add(
            InlineKeyboardButton("🗑 Удалить сессию", callback_data="delete_session")
        )
        text = "Пожалуйста, войдите в свою сессию."
    else:
        text = "Сессия не найдена. Обратитесь к оператору."

    edit_ui(user_id, chat_id, text, markup)


def show_main_menu(user_id, chat_id):
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("✉ Отправить сообщение", callback_data="send_message"))
    markup.add(InlineKeyboardButton("❌ Закрыть сессию", callback_data="close_session"))

    edit_ui(user_id, chat_id, "Выберите действие:", markup)


def show_group_menu(user_id, chat_id):
    chats = load_json(CHATS_FILE)
    permissions = load_json(PERMISSIONS_FILE)

    allowed = permissions.get(str(user_id), [])
    visible = [key for key in allowed if key in chats]

    markup = InlineKeyboardMarkup()

    if not visible:
        markup.add(InlineKeyboardButton("⬅ Назад", callback_data="back_main"))
        edit_ui(user_id, chat_id, "⛔ Нет доступных чатов.", markup)
        return

    for chat_key in visible:
        markup.add(
            InlineKeyboardButton(
                chats[chat_key]["name"],
                callback_data=f"chat_{chat_key}"
            )
        )

    markup.add(InlineKeyboardButton("⬅ Назад", callback_data="back_main"))
    edit_ui(user_id, chat_id, "Выберите чат:", markup)

# =========================
# Handlers
# =========================

@bot.message_handler(commands=['start'])
def start_handler(message):
    user_id = message.from_user.id
    chat_id = message.chat.id

    if not is_authorized(user_id):
        bot.reply_to(message, "⛔ Доступ запрещён.")
        return

    show_login(user_id, chat_id)


@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call):
    user_id = call.from_user.id
    chat_id = call.message.chat.id

    if call.data == "enter_password":
        markup = InlineKeyboardMarkup()
        markup.add(InlineKeyboardButton("⬅ Назад", callback_data="back_login"))
        edit_ui(user_id, chat_id, "Введите пароль:", markup)
        bot.register_next_step_handler_by_chat_id(chat_id, process_password)

    elif call.data == "send_message":
        show_group_menu(user_id, chat_id)

    elif call.data.startswith("chat_"):
        chats = load_json(CHATS_FILE)
        permissions = load_json(PERMISSIONS_FILE)

        chat_key = call.data.replace("chat_", "")
        allowed = permissions.get(str(user_id), [])

        if chat_key not in allowed:
            bot.answer_callback_query(call.id, "⛔ Нет доступа")
            return

        chat_data = chats.get(chat_key)
        if not chat_data:
            return

        markup = InlineKeyboardMarkup()
        markup.add(InlineKeyboardButton("⬅ Назад", callback_data="back_main"))

        edit_ui(
            user_id,
            chat_id,
            f"Введите сообщение для:\n{chat_data['name']}",
            markup
        )

        bot.register_next_step_handler_by_chat_id(
            chat_id,
            prepare_message_confirmation,
            chat_data["url"],
            chat_data["name"]
        )

    elif call.data == "confirm_send":
        if user_id in PENDING_MESSAGES and user_id in ACTIVE_BROWSERS:
            data = PENDING_MESSAGES.pop(user_id)

            ACTIVE_BROWSERS[user_id]["queue"].put({
                "type": "send_message",
                "url": data["url"],
                "text": data["text"]
            })

        show_main_menu(user_id, chat_id)

    elif call.data == "cancel_send":
        if user_id in PENDING_MESSAGES:
            del PENDING_MESSAGES[user_id]
        show_main_menu(user_id, chat_id)

    elif call.data == "close_session":
        close_user_session(user_id)
        show_login(user_id, chat_id)

    elif call.data == "delete_session":
        close_user_session(user_id)

        session_map = load_json(MAP_FILE)
        session_name = session_map.get(str(user_id))

        # 🗑 Удаляем .enc файл
        if session_name:
            enc_path = Path(SESSIONS_DIR) / f"{session_name}.enc"
            if enc_path.exists():
                try:
                    enc_path.unlink()
                except Exception as e:
                    print("Ошибка удаления .enc:", e)

        # Удаляем из session_map
        if str(user_id) in session_map:
            del session_map[str(user_id)]
            with open(MAP_FILE, "w", encoding="utf-8") as f:
                json.dump(session_map, f, indent=4, ensure_ascii=False)

        show_login(user_id, chat_id)


    elif call.data == "back_main":
        show_main_menu(user_id, chat_id)

    elif call.data == "back_login":
        show_login(user_id, chat_id)

# =========================
# Пароль
# =========================
def process_password(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    password = message.text.strip()

    try:
        bot.delete_message(chat_id, message.message_id)
    except:
        pass

    session_name = get_session_name(user_id)
    if not session_name:
        show_login(user_id, chat_id)
        return

    enc_path = Path(SESSIONS_DIR) / f"{session_name}.enc"

    if not enc_path.exists():
        bot.send_message(chat_id, "❌ Файл сессии не найден.")
        return

    try:
        with open(enc_path, "rb") as f:
            file_data = f.read()

        if len(file_data) < 17:
            bot.send_message(chat_id, "❌ Файл сессии повреждён.")
            return

        salt = file_data[:16]
        encrypted_data = file_data[16:]

        key = derive_key(password, salt)
        decrypted = Fernet(key).decrypt(encrypted_data)
        storage_dict = json.loads(decrypted.decode())

    except InvalidToken:
        bot.send_message(chat_id, "❌ Неверный пароль.")
        return

    except Exception as e:
        print("LOGIN ERROR:", e)
        bot.send_message(chat_id, "❌ Ошибка открытия сессии.")
        return

    q = queue.Queue()
    thread = threading.Thread(
        target=browser_worker,
        args=(user_id, storage_dict, q),
        daemon=True
    )
    thread.start()

    ACTIVE_BROWSERS[user_id] = {
        "thread": thread,
        "queue": q
    }

    show_main_menu(user_id, chat_id)

# =========================
# Подтверждение
# =========================

def prepare_message_confirmation(message, url, chat_name):
    user_id = message.from_user.id
    chat_id = message.chat.id
    text = message.text.strip()

    try:
        bot.delete_message(chat_id, message.message_id)
    except:
        pass

    if user_id not in ACTIVE_BROWSERS:
        show_login(user_id, chat_id)
        return

    PENDING_MESSAGES[user_id] = {
        "url": url,
        "text": text,
        "chat_name": chat_name
    }

    markup = InlineKeyboardMarkup()
    markup.add(
        InlineKeyboardButton("✅ Отправить", callback_data="confirm_send"),
        InlineKeyboardButton("❌ Отмена", callback_data="cancel_send")
    )

    edit_ui(
        user_id,
        chat_id,
        f"❓ Точно отправить сообщение:\n\n"
        f"📨 {text}\n\n"
        f"в чат:\n💬 {chat_name} ?",
        markup
    )

# =========================
# Закрытие
# =========================

def close_user_session(user_id):
    if user_id in ACTIVE_BROWSERS:
        ACTIVE_BROWSERS[user_id]["queue"].put({"type": "close"})
        del ACTIVE_BROWSERS[user_id]

# =========================
# Запуск
# =========================

if __name__ == "__main__":
    print("Бот запущен...")
    bot.infinity_polling()


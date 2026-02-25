import os
import json
import base64
import telebot
import threading
import queue
import time
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

# список user_id у кого был активен онлайн-режим чтения (для уведомления после перезапуска)
READING_USERS_FILE = "reading_users.json"

ACTIVE_BROWSERS = {}     # user_id -> {thread, queue, close_event, tg_chat_id, reading_active, reading_chat_key/name/url}
USER_UI_MESSAGE = {}     # user_id -> message_id (один "экран" UI)
PENDING_MESSAGES = {}    # user_id -> {url,text,chat_name}

# forwarded chat-messages to user (для кнопки «Скрыть сообщения») — только для текущего читаемого чата
FORWARDED_MSG_IDS = {}   # user_id -> [msg_id, ...]
LAST_FORWARDED_ID = {}   # user_id -> last_msg_id

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


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except:
            return default


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


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


def add_reading_user(user_id: int):
    lst = load_json(READING_USERS_FILE, [])
    if user_id not in lst:
        lst.append(user_id)
        save_json(READING_USERS_FILE, lst)


def remove_reading_user(user_id: int):
    lst = load_json(READING_USERS_FILE, [])
    if user_id in lst:
        lst = [x for x in lst if x != user_id]
        save_json(READING_USERS_FILE, lst)


TOKEN = load_encrypted_token()
WHITELIST = load_whitelist()

bot = telebot.TeleBot(TOKEN)

# =========================
# Session helpers
# =========================

def has_session(user_id):
    session_map = load_json(MAP_FILE, {})
    return str(user_id) in session_map


def get_session_name(user_id):
    session_map = load_json(MAP_FILE, {})
    return session_map.get(str(user_id))


def is_authorized(user_id):
    return str(user_id) in WHITELIST


def edit_ui(user_id, chat_id, text, markup):
    """
    Экранный UI: один "главный" message, который мы редактируем.
    """
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
# Чтение сообщений (DOM парсер)
# =========================

def _extract_messages_from_page(page):
    out = []
    wrappers = page.query_selector_all("div.bordersWrapper")

    for wrapper in wrappers:
        try:
            bubble = wrapper.query_selector("div.bubble")
            if not bubble:
                continue

            wrapper_class = wrapper.get_attribute("class") or ""
            direction = "OUT" if "--right" in wrapper_class else "IN"

            name_el = bubble.query_selector(".header span.name span.text")
            sender = name_el.inner_text().strip() if name_el else "Вы"

            time_el = bubble.query_selector(".meta span.text")
            msg_time = time_el.inner_text().strip() if time_el else "??:??"

            text_elements = bubble.query_selector_all("span.text")
            message_text = ""

            for el in text_elements:
                parent_class = el.evaluate("e => e.parentElement.className || ''")
                if "meta" in parent_class:
                    continue
                if "name" in parent_class:
                    continue
                if "header" in parent_class:
                    continue

                text = el.inner_text().strip()
                if text and text != sender and text != msg_time:
                    message_text = text
                    break

            if not message_text:
                continue

            out.append((direction, sender, msg_time, message_text))
        except:
            pass

    return out


def _send_forwarded_message(user_id, tg_chat_id, formatted, chat_key_for_buttons):
    """
    Отправляет сообщение пользователю и держит кнопку «Скрыть сообщения» под последним сообщением.
    """
    prev_id = LAST_FORWARDED_ID.get(user_id)
    if prev_id:
        try:
            bot.edit_message_reply_markup(tg_chat_id, prev_id, reply_markup=None)
        except:
            pass

    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("🙈 Скрыть сообщения", callback_data=f"hide_messages:{chat_key_for_buttons}"))
    kb.add(InlineKeyboardButton("⛔ Остановить чтение", callback_data=f"stop_reading:{chat_key_for_buttons}"))

    m = bot.send_message(tg_chat_id, formatted, parse_mode="HTML", reply_markup=kb)

    FORWARDED_MSG_IDS.setdefault(user_id, []).append(m.message_id)
    LAST_FORWARDED_ID[user_id] = m.message_id


# =========================
# Playwright Worker (одно чтение на пользователя)
# =========================

def browser_worker(user_id, storage_state, command_queue, close_event):
    """
    Один воркер на пользователя.
    Чтение ограничено одним чатом одновременно.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(storage_state=storage_state)

        # отдельная вкладка под отправку
        send_page = context.new_page()
        send_page.goto("https://web.max.ru/")

        read_state = {
            "active": False,
            "chat_key": None,
            "name": None,
            "url": None,
            "page": None,
            "printed": set()
        }

        def _start_read(chat_key, url, name, tg_chat_id):
            if read_state["active"]:
                # уже читаем — игнорируем
                return False

            page = context.new_page()
            page.goto(url)
            page.wait_for_selector("div.bordersWrapper")

            for _ in range(10):
                page.mouse.wheel(0, -5000)
                time.sleep(1)

            read_state.update({
                "active": True,
                "chat_key": chat_key,
                "name": name,
                "url": url,
                "page": page,
                "printed": set()
            })

            # системное сообщение о запуске тоже учитываем в "скрыть"
            try:
                m = bot.send_message(tg_chat_id, f"📡 Онлайн-чтение запущено: <b>{name}</b>", parse_mode="HTML")
                FORWARDED_MSG_IDS.setdefault(user_id, []).append(m.message_id)
            except:
                pass

            return True

        def _stop_read():
            if not read_state["active"]:
                return
            try:
                if read_state["page"]:
                    read_state["page"].close()
            except:
                pass
            read_state.update({
                "active": False,
                "chat_key": None,
                "name": None,
                "url": None,
                "page": None,
                "printed": set()
            })

        try:
            while not close_event.is_set():
                try:
                    cmd = command_queue.get(timeout=0.6)
                except:
                    cmd = None

                if cmd:
                    ctype = cmd.get("type")

                    if ctype == "send_message":
                        try:
                            send_page.goto(cmd["url"])
                            editor = send_page.locator('div[data-lexical-editor="true"]')
                            editor.wait_for(timeout=15000)
                            editor.click()
                            send_page.keyboard.type(cmd["text"], delay=30)
                            send_page.locator('button[aria-label="Отправить сообщение"]').click()
                        except Exception as e:
                            print("Send error:", e)

                    elif ctype == "start_read":
                        try:
                            _start_read(cmd["chat_key"], cmd["url"], cmd["name"], cmd["tg_chat_id"])
                        except Exception as e:
                            try:
                                bot.send_message(cmd["tg_chat_id"], f"❌ Ошибка запуска чтения: {e}")
                            except:
                                pass

                    elif ctype == "stop_read":
                        _stop_read()

                    elif ctype == "close":
                        _stop_read()
                        close_event.set()
                        break

                # опрос активного чата
                if read_state["active"] and read_state["page"]:
                    tg_chat_id = ACTIVE_BROWSERS.get(user_id, {}).get("tg_chat_id", user_id)
                    chat_key = read_state["chat_key"]
                    chat_name = read_state["name"]
                    page = read_state["page"]
                    printed = read_state["printed"]

                    try:
                        msgs = _extract_messages_from_page(page)
                    except:
                        msgs = []

                    for direction, sender, msg_time, message_text in msgs:
                        unique_id = f"{sender}_{msg_time}_{message_text}"
                        if unique_id in printed:
                            continue
                        printed.add(unique_id)

                        arrow = "➡️" if direction == "OUT" else "⬅️"
                        formatted = (
                            f"💬 <b>{chat_name}</b>\n"
                            f"{arrow} <b>{sender}</b>\n"
                            f"🕒 {msg_time}\n"
                            f"📨 {message_text}"
                        )
                        try:
                            _send_forwarded_message(user_id, tg_chat_id, formatted, chat_key)
                        except:
                            pass

        finally:
            try:
                _stop_read()
            except:
                pass
            try:
                send_page.close()
            except:
                pass
            try:
                browser.close()
            except:
                pass


# =========================
# UI
# =========================

def show_login(user_id, chat_id):
    markup = InlineKeyboardMarkup()

    if has_session(user_id):
        markup.add(InlineKeyboardButton("🔐 Войти в сессию", callback_data="enter_password"))
        markup.add(InlineKeyboardButton("🗑 Удалить сессию", callback_data="delete_session"))
        text = "Пожалуйста, войдите в свою сессию."
    else:
        text = "Сессия не найдена. Обратитесь к оператору."

    edit_ui(user_id, chat_id, text, markup)


def show_main_menu(user_id, chat_id):
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("✉ Отправить сообщение", callback_data="send_message"))
    markup.add(InlineKeyboardButton("📨 Просмотреть сообщения", callback_data="view_messages"))

    # если читаем чат — покажем стоп-кнопку в меню
    if user_id in ACTIVE_BROWSERS and ACTIVE_BROWSERS[user_id].get("reading_active"):
        name = ACTIVE_BROWSERS[user_id].get("reading_chat_name") or "чат"
        chat_key = ACTIVE_BROWSERS[user_id].get("reading_chat_key") or "chat"
        markup.add(InlineKeyboardButton(f"⛔ Остановить чтение ({name})", callback_data=f"stop_reading:{chat_key}"))

    markup.add(InlineKeyboardButton("❌ Закрыть сессию", callback_data="close_session"))
    edit_ui(user_id, chat_id, "Выберите действие:", markup)


def show_chat_menu(user_id, chat_id, mode):
    """
    mode: "send" | "read"
    """
    chats = load_json(CHATS_FILE, {})
    permissions = load_json(PERMISSIONS_FILE, {})

    allowed = permissions.get(str(user_id), [])
    visible = [key for key in allowed if key in chats]

    markup = InlineKeyboardMarkup()

    if not visible:
        markup.add(InlineKeyboardButton("⬅ Назад", callback_data="back_main"))
        edit_ui(user_id, chat_id, "⛔ Нет доступных чатов.", markup)
        return

    for chat_key in visible:
        cb = f"{mode}_{chat_key}"
        markup.add(InlineKeyboardButton(chats[chat_key]["name"], callback_data=cb))

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

    # реклама прокси
    offer = (
        "✨ <b>Оставайтесь на связи</b> — подключайте встроенное прокси\n"
        "Пользуйтесь чем удобно, а не чем приказали ✅\n\n"
        "🛡 <a href=\"tg://proxy?server=tg.liberty-tech.online&port=443&secret=a4bc6821c58eee9b48038b104950504a\">Либерти авто</a>\n"
        "🛡 <a href=\"tg://proxy?server=109.107.166.49&port=443&secret=a4bc6821c58eee9b48038b104950504a\">Либерти ручной первый</a>\n"
        "🛡 <a href=\"tg://proxy?server=146.103.109.134&port=443&secret=a4bc6821c58eee9b48038b104950504a\">Либерти ручной второй</a>\n\n"
        "🌿 <a href=\"https://t.me/proxy?server=77.73.66.85&port=443&secret=7356e5c8f793f16a2050f66debc080a4\">Blum первый</a>\n"
        "🌿 <a href=\"https://t.me/proxy?server=77.73.69.47&port=443&secret=a0cbda6522a6b40cbd94f668f839ce72\">Blum второй</a>\n\n"
        "🔐 <b>Пожалуйста, войдите в сессию</b> — нажмите кнопку ниже."
    )

    try:
        bot.send_message(
            chat_id,
            offer,
            parse_mode="HTML",
            disable_web_page_preview=True
        )
    except:
        pass

    # Дальше — стандартный экран входа в сессию
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
        if user_id not in ACTIVE_BROWSERS:
            show_login(user_id, chat_id)
            return
        show_chat_menu(user_id, chat_id, mode="send")

    elif call.data == "view_messages":
        if user_id not in ACTIVE_BROWSERS:
            show_login(user_id, chat_id)
            return
        show_chat_menu(user_id, chat_id, mode="read")

    elif call.data.startswith("send_") or call.data.startswith("read_"):
        chats = load_json(CHATS_FILE, {})
        permissions = load_json(PERMISSIONS_FILE, {})

        mode, chat_key = call.data.split("_", 1)
        allowed = permissions.get(str(user_id), [])

        if chat_key not in allowed:
            bot.answer_callback_query(call.id, "⛔ Нет доступа")
            return

        chat_data = chats.get(chat_key)
        if not chat_data:
            return

        if user_id not in ACTIVE_BROWSERS:
            show_login(user_id, chat_id)
            return

        if mode == "send":
            markup = InlineKeyboardMarkup()
            markup.add(InlineKeyboardButton("⬅ В меню", callback_data="back_main"))

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
        else:
            # mode == "read" (ограничение: только один чат)
            if ACTIVE_BROWSERS[user_id].get("reading_active"):
                cur_name = ACTIVE_BROWSERS[user_id].get("reading_chat_name") or "чат"
                cur_key = ACTIVE_BROWSERS[user_id].get("reading_chat_key") or "chat"

                markup = InlineKeyboardMarkup()
                markup.add(InlineKeyboardButton(f"⛔ Остановить чтение ({cur_name})", callback_data=f"stop_reading:{cur_key}"))
                markup.add(InlineKeyboardButton("⬅ В меню", callback_data="back_main"))

                edit_ui(
                    user_id,
                    chat_id,
                    f"⚠️ У вас уже запущено онлайн-чтение:\n<b>{cur_name}</b>\n\n"
                    f"Чтобы открыть новое — сначала остановите текущее.",
                    markup
                )
                return

            # стартуем чтение
            ACTIVE_BROWSERS[user_id]["reading_active"] = True
            ACTIVE_BROWSERS[user_id]["reading_chat_key"] = chat_key
            ACTIVE_BROWSERS[user_id]["reading_chat_name"] = chat_data["name"]
            ACTIVE_BROWSERS[user_id]["reading_chat_url"] = chat_data["url"]

            # добавить в список активных чтений (на случай перезапуска)
            add_reading_user(user_id)

            ACTIVE_BROWSERS[user_id]["queue"].put({
                "type": "start_read",
                "chat_key": chat_key,
                "url": chat_data["url"],
                "name": chat_data["name"],
                "tg_chat_id": ACTIVE_BROWSERS[user_id].get("tg_chat_id", chat_id)
            })

            markup = InlineKeyboardMarkup()
            markup.add(InlineKeyboardButton("⛔ Остановить чтение", callback_data=f"stop_reading:{chat_key}"))
            markup.add(InlineKeyboardButton("⬅ В меню", callback_data="back_main"))
            edit_ui(user_id, chat_id, f"📡 Чтение запущено:\n{chat_data['name']}", markup)

    elif call.data.startswith("stop_reading:"):
        if user_id in ACTIVE_BROWSERS:
            # остановка чтения (одно на юзера)
            ACTIVE_BROWSERS[user_id]["queue"].put({"type": "stop_read"})

            ACTIVE_BROWSERS[user_id]["reading_active"] = False
            ACTIVE_BROWSERS[user_id]["reading_chat_key"] = None
            ACTIVE_BROWSERS[user_id]["reading_chat_name"] = None
            ACTIVE_BROWSERS[user_id]["reading_chat_url"] = None

            remove_reading_user(user_id)

        show_main_menu(user_id, chat_id)

    elif call.data.startswith("hide_messages:"):
        # скрыть сообщения текущего читаемого чата (включая "📡 Онлайн-чтение запущено ...")
        ids = FORWARDED_MSG_IDS.get(user_id, [])
        for mid in ids:
            try:
                bot.delete_message(chat_id, mid)
            except:
                pass

        FORWARDED_MSG_IDS[user_id] = []
        LAST_FORWARDED_ID[user_id] = None

        bot.answer_callback_query(call.id, "🙈 Сообщения скрыты")
        show_main_menu(user_id, chat_id)

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

        session_map = load_json(MAP_FILE, {})
        session_name = session_map.get(str(user_id))

        if session_name:
            enc_path = Path(SESSIONS_DIR) / f"{session_name}.enc"
            if enc_path.exists():
                try:
                    enc_path.unlink()
                except Exception as e:
                    print("Ошибка удаления .enc:", e)

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
    close_event = threading.Event()

    thread = threading.Thread(
        target=browser_worker,
        args=(user_id, storage_dict, q, close_event),
        daemon=True
    )
    thread.start()

    ACTIVE_BROWSERS[user_id] = {
        "thread": thread,
        "queue": q,
        "close_event": close_event,
        "tg_chat_id": chat_id,
        "reading_active": False,
        "reading_chat_key": None,
        "reading_chat_name": None,
        "reading_chat_url": None
    }

    show_main_menu(user_id, chat_id)


# =========================
# Подтверждение отправки
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
        # остановить чтение
        try:
            ACTIVE_BROWSERS[user_id]["queue"].put({"type": "stop_read"})
        except:
            pass

        try:
            ACTIVE_BROWSERS[user_id]["queue"].put({"type": "close"})
        except:
            pass

        try:
            ACTIVE_BROWSERS[user_id]["close_event"].set()
        except:
            pass

        # убрать из списка активных чтений на перезапуск
        remove_reading_user(user_id)

        del ACTIVE_BROWSERS[user_id]

    # чистим трекинг пересланных сообщений
    FORWARDED_MSG_IDS.pop(user_id, None)
    LAST_FORWARDED_ID.pop(user_id, None)


# =========================
# Уведомление после перезапуска
# =========================

def notify_restart_reading_users():
    """
    Если бот перезапустился — online-режим в браузерах отвалился.
    Уведомляем тех, кто был в reading_users.json.
    После УСПЕШНОЙ отправки удаляем id из списка.
    """
    ids = load_json(READING_USERS_FILE, [])
    if not ids:
        return

    remaining = []
    for uid in ids:
        try:
            bot.send_message(
                uid,
                "♻️ Бот был перезапущен.\n\n"
                "Чтобы снова получать сообщения в онлайн-режиме:\n"
                "1) Откройте сессию (введите пароль)\n"
                "2) Запустите онлайн-чтение заново."
            )
            # успешно — не добавляем в remaining
        except:
            # если не удалось (например, пользователь заблокировал бота) — оставим
            remaining.append(uid)

    save_json(READING_USERS_FILE, remaining)


# =========================
# Запуск
# =========================

if __name__ == "__main__":
    print("Бот запущен...")

    # уведомим пользователей, у кого было активное чтение до перезапуска
    notify_restart_reading_users()

    bot.infinity_polling()

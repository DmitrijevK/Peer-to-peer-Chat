import socket
import threading
import base64
import hashlib
import os
import hmac
import socks
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from ecdsa import ECDH, NIST256p, SigningKey, VerifyingKey

BLOCK_SIZE = Blowfish.block_size
LOG_FILE = "chat_log.txt"

shared_key = b''
hmac_key = b''

def encrypt(secret_key, data):
    iv = os.urandom(BLOCK_SIZE)
    cipher = Blowfish.new(secret_key, Blowfish.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode(), BLOCK_SIZE))
    return base64.b64encode(iv + ciphertext)

def decrypt(secret_key, data):
    raw = base64.b64decode(data)
    iv = raw[:BLOCK_SIZE]
    ciphertext = raw[BLOCK_SIZE:]
    cipher = Blowfish.new(secret_key, Blowfish.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE).decode()

def sign_message(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()

def verify_signature(key, message, signature):
    return hmac.compare_digest(sign_message(key, message), signature)

def exchange_keys(conn, is_server):
    global shared_key, hmac_key
    sk = SigningKey.generate(curve=NIST256p)
    ecdh = ECDH(curve=NIST256p, private_key=sk)
    vk = sk.get_verifying_key()
    conn.send(vk.to_string())
    peer_vk_bytes = conn.recv(1024)
    peer_vk = VerifyingKey.from_string(peer_vk_bytes, curve=NIST256p)
    ecdh.load_received_public_key(peer_vk)
    shared_key = ecdh.generate_sharedsecret_bytes()
    hmac_key = hashlib.sha256(shared_key).digest()
    print("[✓] Общий ключ успешно установлен")

def create_proxy_socket(host, port, use_tor=False, proxy_addr=None, proxy_port=None):
    s = socks.socksocket()
    if use_tor:
        print("[TOR] Используем Tor через SOCKS5 127.0.0.1:9050")
        s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    elif proxy_addr and proxy_port:
        print(f"[Proxy] Используем SOCKS5-прокси {proxy_addr}:{proxy_port}")
        s.set_proxy(socks.SOCKS5, proxy_addr, int(proxy_port))
    else:
        print("[!] Без прокси — обычное соединение")
    return s

def send_message(conn):
    while True:
        msg = input()
        if msg.lower() == "exit":
            conn.close()
            break
        encrypted = encrypt(shared_key, msg)
        signature = sign_message(hmac_key, encrypted)
        conn.send(signature + b'||' + encrypted)

def receive_message(conn):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            signature, encrypted = data.split(b'||', 1)
            if not verify_signature(hmac_key, encrypted, signature):
                print("[!] ⚠ Неверная подпись!")
                continue
            decrypted = decrypt(shared_key, encrypted)
            print(f"[Peer]: {decrypted}")
            log_message("[Peer]: " + decrypted)
        except Exception as e:
            print("[!] Ошибка при получении:", e)
            break

def log_message(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def start_chat(is_server, host='127.0.0.1', port=5000, use_tor=False, proxy_addr=None, proxy_port=None):
    global shared_key, hmac_key

    if is_server:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"[Server] Ожидание подключения на {host}:{port}...")
        conn, addr = server_socket.accept()
        print(f"[✓] Клиент подключён: {addr}")
        exchange_keys(conn, is_server=True)
    else:
        conn = create_proxy_socket(host, port, use_tor, proxy_addr, proxy_port)
        print(f"[Client] Подключение к {host}:{port}...")
        conn.connect((host, port))
        print("[✓] Подключено")
        exchange_keys(conn, is_server=False)

    threading.Thread(target=receive_message, args=(conn,), daemon=True).start()
    send_message(conn)

if __name__ == "__main__":
    mode = input("Выберите режим (server/client): ").strip().lower()

    if mode == "client":
        use_tor = input("Использовать TOR? (y/n): ").strip().lower() == "y"
        if not use_tor:
            use_proxy = input("Использовать SOCKS5-прокси? (y/n): ").strip().lower() == "y"
            if use_proxy:
                proxy_host = input("Адрес прокси (например, 127.0.0.1): ")
                proxy_port = input("Порт прокси (например, 1080): ")
                target_host = input("Хост сервера: ")
                target_port = int(input("Порт сервера: "))
                start_chat(False, target_host, target_port, False, proxy_host, proxy_port)
            else:
                target_host = input("Хост сервера: ")
                target_port = int(input("Порт сервера: "))
                start_chat(False, target_host, target_port)
        else:
            target_host = input("Хост сервера (обычно .onion не поддерживается напрямую): ")
            target_port = int(input("Порт сервера: "))
            start_chat(False, target_host, target_port, use_tor=True)
    else:
        host = input("Введите IP сервера (по умолчанию 0.0.0.0): ").strip() or "0.0.0.0"
        port = int(input("Введите порт: ").strip() or 5000)
        start_chat(True, host, port)

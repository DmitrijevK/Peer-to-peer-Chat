import socket
import threading
import base64
import hashlib
import os
import hmac
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from ecdsa import ECDH, NIST256p, SigningKey, VerifyingKey

BLOCK_SIZE = Blowfish.block_size  # 8 bytes

LOG_FILE = "chat_log.txt"

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
    hmac_key = hashlib.sha256(shared_key).digest()[:32]
    print("[✓] Общий ключ ECDH успешно получен")

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
                print("[!] ⚠ Подпись не прошла проверку!")
                continue

            decrypted = decrypt(shared_key, encrypted)
            print(f"[Peer]: {decrypted}")
            log_message("[Peer]: " + decrypted)
        except Exception as e:
            print("[!] Ошибка:", e)
            break

def log_message(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")


def start_chat(is_server, host='127.0.0.1', port=5000):
    if is_server:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"[Server] Ожидание подключения на {host}:{port}...")
        conn, addr = server_socket.accept()
        print(f"[✓] Клиент подключён: {addr}")
        exchange_keys(conn, is_server=True)
    else:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((host, port))
        print(f"[✓] Подключено к серверу {host}:{port}")
        exchange_keys(conn, is_server=False)

    threading.Thread(target=receive_message, args=(conn,), daemon=True).start()
    send_message(conn)

if __name__ == "__main__":
    mode = input("Выберите режим (server/client): ").strip().lower()
    start_chat(is_server=(mode == "server"))

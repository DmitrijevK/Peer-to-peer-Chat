import socket
import threading
import base64
import hashlib
import os
from Crypto.Cipher import AES

# encrypt text
def encrypt(secret_key, data):
    BLOCK_SIZE = 16
    PADDING = '{'

    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    cipher = AES.new(secret_key)
    encoded = EncodeAES(cipher, data)
    return encoded

# decrypt text
def decrypt(secret_key, data):
    PADDING = '{'

    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
    cipher = AES.new(secret_key)
    decoded = DecodeAES(cipher, data)
    return decoded

# function hashed
def hash_string(string):
    hash_string = hashlib.sha256(string.encode()).hexdigest()
    return hash_string

# Secretkey trade
def exchange_keys():
    global secret_key
    secret_key = os.urandom(16)
    hashed_key = hash_string(secret_key)
    conn.send(hashed_key.encode())
    response = conn.recv(1024).decode()
    if response == hashed_key:
        print('Secret key exchange successful')
    else:
        print('Secret key exchange failed')

# Send Message 
def send_message():
    while True:
        message = input('Enter your message: ')
        if message == 'exit':
            break
        encrypted_message = encrypt(secret_key, message)
        conn.send(encrypted_message)

# Get Message
def receive_message():
    while True:
        data = conn.recv(1024)
        if not data:
            break
        decrypted_data = decrypt(secret_key, data)

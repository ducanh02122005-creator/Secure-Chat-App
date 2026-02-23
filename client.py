import socket
import threading
import json
import struct
import queue

from crypto_utils import *


HOST = "127.0.0.1"
PORT = 12345

response_queue = queue.Queue()
private_key = None
username = None


# ======================
# JSON
# ======================

def send_json(conn, data):

    raw = json.dumps(data).encode()

    conn.sendall(struct.pack("!I", len(raw)))
    conn.sendall(raw)


def recv_json(conn):

    rawlen = recvall(conn, 4)

    if not rawlen:
        return None

    length = struct.unpack("!I", rawlen)[0]

    raw = recvall(conn, length)

    return json.loads(raw.decode())


def recvall(conn, n):

    data = b''

    while len(data) < n:

        packet = conn.recv(n - len(data))

        if not packet:
            return None

        data += packet

    return data


# ======================
# RECEIVER THREAD
# ======================

def receiver(conn):

    global private_key

    while True:

        msg = recv_json(conn)

        if msg["type"] == "incoming":

            text = decrypt_message(
                private_key,
                msg["wrapped_key"],
                msg["nonce"],
                msg["ciphertext"]
            )

            print(f"\n[{msg['from']}] {text}")

        else:

            response_queue.put(msg)


# ======================
# MAIN
# ======================

conn = socket.socket()

conn.connect((HOST, PORT))

threading.Thread(
    target=receiver,
    args=(conn,),
    daemon=True
).start()


while True:

    print("\n1 Register")
    print("2 Login")
    print("3 Send message")
    print("4 Exit")

    choice = input("> ")


    if choice == "1":

        username = input("Username: ")
        password = input("Password: ")

        private_key, public_key = generate_rsa_keys()

        save_private_key(username, private_key)

        send_json(conn, {

            "type": "register",
            "username": username,
            "password": password,
            "public_key": serialize_public_key(public_key)

        })

        print(response_queue.get())


    elif choice == "2":

        username = input("Username: ")
        password = input("Password: ")

        private_key = load_private_key(username)

        send_json(conn, {

            "type": "login",
            "username": username,
            "password": password

        })

        print(response_queue.get())


    elif choice == "3":

        target = input("To: ")

        text = input("Message: ")

        send_json(conn, {

            "type": "get_pubkey",
            "username": target

        })

        resp = response_queue.get()

        pub = deserialize_public_key(resp["public_key"])

        encrypted = encrypt_message(pub, text)

        encrypted["type"] = "send"
        encrypted["to"] = target

        send_json(conn, encrypted)

        print(response_queue.get())


    elif choice == "4":

        break
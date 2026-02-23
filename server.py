import socket
import threading
import json
import struct

HOST = "127.0.0.1"
PORT = 12345

users = {}
lock = threading.Lock()


# ======================
# JSON COMMUNICATION
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
# CLIENT HANDLER
# ======================

def handle_client(conn):

    username = None

    try:

        while True:

            msg = recv_json(conn)

            if msg is None:
                break

            t = msg["type"]

            if t == "register":

                with lock:

                    if msg["username"] in users:

                        send_json(conn, {"type": "fail"})

                    else:

                        users[msg["username"]] = {
                            "password": msg["password"],
                            "public_key": msg["public_key"],
                            "conn": None
                        }

                        send_json(conn, {"type": "ok"})

            elif t == "login":

                with lock:

                    if msg["username"] in users and \
                       users[msg["username"]]["password"] == msg["password"]:

                        username = msg["username"]

                        users[username]["conn"] = conn

                        send_json(conn, {"type": "ok"})

                    else:

                        send_json(conn, {"type": "fail"})

            elif t == "get_pubkey":

                with lock:

                    if msg["username"] in users:

                        send_json(conn, {
                            "type": "pubkey",
                            "public_key":
                            users[msg["username"]]["public_key"]
                        })

            elif t == "send":

                with lock:

                    target = users.get(msg["to"])

                    if target and target["conn"]:

                        send_json(target["conn"], {

                            "type": "incoming",
                            "from": username,
                            "wrapped_key": msg["wrapped_key"],
                            "nonce": msg["nonce"],
                            "ciphertext": msg["ciphertext"]

                        })

                        send_json(conn, {"type": "ok"})

    finally:

        if username:

            with lock:
                users[username]["conn"] = None

        conn.close()


# ======================
# MAIN
# ======================

server = socket.socket()

server.bind((HOST, PORT))

server.listen()

print("SERVER RUNNING...")

while True:

    conn, addr = server.accept()

    threading.Thread(
        target=handle_client,
        args=(conn,),
        daemon=True
    ).start()
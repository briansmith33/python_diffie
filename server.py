from aes import AESCipher
from threading import Thread
import hashlib
import socket
import json
import ssl
import jwt


class Server(Thread):
    def __init__(self, port, key_length=540, generator=2):
        super().__init__()
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.n_bytes = key_length
        self.generator = generator
        with open('primes.json', 'r') as f:
            primes = json.load(f)
        self.prime = int(primes["18"], 16)
        self.priv_key = self.generate_private_key()
        self.pub_key = self.generate_public_key()
        self.running = False
        self.connections = {}

    def generate_private_key(self):
        return int.from_bytes(ssl.RAND_bytes(self.n_bytes), byteorder='big')

    def generate_public_key(self):
        return pow(self.generator, self.priv_key, self.prime)

    def perform_key_exchange(self, conn):
        remote_pub_key = int.from_bytes(conn.recv(BUFFER * 20).strip(b"\x10"), byteorder='big')
        response = self.pub_key.to_bytes(self.pub_key.bit_length() // 8 + 1, byteorder="big")
        response += b"\x10" * ((BUFFER * 10) - len(response))
        conn.send(response)
        shared_secret = pow(remote_pub_key, self.priv_key, self.prime)
        shared_secret_bytes = shared_secret.to_bytes(shared_secret.bit_length() // 8 + 1, byteorder="big")
        return hashlib.sha256(shared_secret_bytes).hexdigest()

    def send(self, peer, event_type, data=""):
        peer_data = self.connections[peer]
        conn = peer_data["conn"]
        cipher = AESCipher(peer_data["key"])
        data = cipher.encrypt(data)
        header = json.dumps({"type": event_type, "length": len(data)})
        header = cipher.encrypt(header)
        header += b"\x10" * (BUFFER - len(header))
        conn.send(header + data)

    def receive(self, peer):
        peer_data = self.connections[peer]
        conn = peer_data["conn"]
        cipher = AESCipher(peer_data["key"])
        header = conn.recv(BUFFER).strip(b"\x10")
        if header:
            header = cipher.decrypt(header)
            header = json.loads(header)
            event_type = header['type']
            msg_len = header['length']
            token = header['token']
            data = conn.recv(msg_len)
            return event_type, cipher.decrypt(data), token

    def broadcast(self, event_type, data, exclude=None):
        if exclude is None:
            exclude = []

        peers = list(self.connections.keys())
        for peer in peers:
            if peer not in exclude:
                peer_conn = self.connections[peer]["conn"]
                self.send(peer_conn, event_type, data)

    def valid_token(self, token, peer):
        try:
            decoded = jwt.decode(token, self.connections[peer]["key"], "HS256")
        except (jwt.InvalidTokenError, jwt.DecodeError):
            return False
        if "ip" in list(decoded.keys()):
            return True
        return False

    def handle_connection(self, peer):
        event_type, data, token = self.receive(peer)
        if event_type != "token validation":
            return

        if not self.valid_token(token, peer):
            return

        conn_data = self.connections[peer]
        print(conn_data)
        conn = conn_data["conn"]
        peers = list(self.connections.keys())
        self.send(peer, "peer list", json.dumps(peers))
        self.broadcast("peer joined", peer, exclude=[peer])

        while True:
            try:
                event_type, data, token = self.receive(peer)
            except ConnectionResetError:
                self.broadcast("peer left", peer, exclude=[peer])
                del self.connections[peer]
                break

            if not self.valid_token(token, peer):
                self.broadcast("peer left", peer, exclude=[peer])
                del self.connections[peer]
                break

            if event_type == "disconnect":
                self.broadcast("peer left", peer, exclude=[peer])
                del self.connections[peer]
                break

            if event_type == "key swap":
                key = self.perform_key_exchange(conn)
                self.connections[peer]["key"] = key
                continue

            if event_type == "message":
                print(data.decode())
                self.send(peer, "received")
                continue

        conn.close()

    def run(self):
        self.socket.bind((HOST, self.port))
        self.socket.listen()
        self.running = True
        print(f"[*] Server listening on port {self.port}. Waiting for incoming connections...")
        while self.running:
            conn, addr = self.socket.accept()
            key = self.perform_key_exchange(conn)
            print(f"[*] Connection accepted from {addr[0]}:{addr[1]}!")
            thread = Thread(target=self.handle_connection, daemon=True, args=(addr[0],))
            self.connections[addr[0]] = {
                "conn": conn,
                "key": key,
                "thread": thread
            }
            thread.start()


if __name__ == "__main__":
    HOST = socket.gethostbyname(socket.gethostname())
    BUFFER = 1024
    PORT = 4444
    Server(PORT).run()


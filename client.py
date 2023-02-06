from aes import AESCipher
from threading import Thread
import hashlib
import socket
import json
import ssl
import jwt


class Client(Thread):
    def __init__(self, key_length=540, generator=2):
        super().__init__()
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.n_bytes = key_length
        self.generator = generator
        with open('primes.json', 'r') as f:
            primes = json.load(f)
        self.prime = int(primes["18"], 16)
        self.priv_key = self.generate_private_key()
        self.pub_key = self.generate_public_key()
        self.aes_key = None
        self.cipher = None
        self.peers = None

    def generate_private_key(self):
        return int.from_bytes(ssl.RAND_bytes(self.n_bytes), byteorder='big')

    def generate_public_key(self):
        return pow(self.generator, self.priv_key, self.prime)

    def perform_key_exchange(self):
        key = self.pub_key.to_bytes(self.pub_key.bit_length() // 8 + 1, byteorder="big")
        key += b"\x10" * ((BUFFER * 20) - len(key))
        self.conn.send(key)
        remote_pub_key = int.from_bytes(self.conn.recv(BUFFER * 20).strip(b"\x10"), byteorder='big')
        shared_secret = pow(remote_pub_key, self.priv_key, self.prime)
        shared_secret_bytes = shared_secret.to_bytes(shared_secret.bit_length() // 8 + 1, byteorder="big")
        return hashlib.sha256(shared_secret_bytes).hexdigest()

    def send(self, event_type, data=""):
        data = self.cipher.encrypt(data)
        token = jwt.encode({"ip": CLIENT_IP}, self.aes_key, algorithm="HS256")
        header = json.dumps({"type": event_type, "length": len(data), "token": token})
        header = self.cipher.encrypt(header)
        header += b"\x10" * (BUFFER - len(header))
        self.conn.send(header + data)

    def receive(self):
        header = self.conn.recv(BUFFER).strip(b"\x10")
        if header:
            header = self.cipher.decrypt(header)
            header = json.loads(header)
            event_type = header['type']
            msg_len = header['length']
            data = self.conn.recv(msg_len)
            return event_type, self.cipher.decrypt(data)

    def listen(self):
        while True:
            try:
                event_type, data = self.receive()
            except ConnectionResetError:
                break

            if event_type == "peer list":
                self.peers = json.loads(data)
                continue

            if event_type == "peer joined":
                self.peers.append(data)
                continue

            if event_type == "peer left":
                self.peers.remove(data)
                continue

            if event_type == "received":
                continue

    def run(self):
        self.conn.connect((HOST, PORT))
        self.aes_key = self.perform_key_exchange()
        self.cipher = AESCipher(self.aes_key)
        self.send("token validation")
        Thread(target=self.listen).start()
        while True:
            message = input(">> ")
            self.send("message", message)


if __name__ == "__main__":
    HOST = socket.gethostbyname(socket.gethostname())
    PORT = 4444
    CLIENT_IP = socket.gethostbyname(socket.gethostname())
    BUFFER = 1024
    Client().run()

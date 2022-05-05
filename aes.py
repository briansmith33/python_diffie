from Crypto.Cipher import AES
from Crypto import Random
import hashlib


class AESCipher:
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def pad(self, text):
        return text + (self.block_size - len(text) % self.block_size) * chr(
            self.block_size - len(text) % self.block_size)

    @staticmethod
    def unpad(text):
        return text[:-ord(text[len(text) - 1:])]

    def encrypt(self, plain_text):
        plain_text = self.pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return iv + encrypted_text

    def decrypt(self, encrypted_text):
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:])
        return self.unpad(plain_text)

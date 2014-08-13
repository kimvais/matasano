from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tools import chunk_into, xor_with_key


class ECB(object):
    def __init__(self, key):
        self.cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    def decrypt(self, data):
        d = self.cipher.decryptor()
        plain = d.update(data) + d.finalize()
        return plain

    def encrypt(self, data):
        e = self.cipher.encryptor()
        return e.update(data) + e.finalize()


class CBC(object):
    def __init__(self, key, iv):
        self.key = key
        self._state = iv

    def decrypt(self, data):
        assert len(data) % 16 == 0
        blocks = chunk_into(data, 16)
        plain = list()
        for block in blocks:
            plain.append(xor_with_key(ECB(self.key).decrypt(block), self._state))
            self._state = block
        return b''.join(plain)

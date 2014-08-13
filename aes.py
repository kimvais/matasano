from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class ECB(object):
    def __init__(self, key):
        self.cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    def decrypt(self, data):
        d = self.cipher.decryptor()
        plain = d.update(data) + d.finalize()
        return plain[:-plain[-1]]
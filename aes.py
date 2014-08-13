import random
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from tools import chunk_into, xor_with_key, pkcs7pad, unpad


class ECB(object):
    def __init__(self, key):
        self.cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    def decrypt(self, data):
        d = self.cipher.decryptor()
        plain = d.update(data) + d.finalize()
        return plain

    def encrypt(self, data):
        if not len(data) % 16 == 0:
            data = pkcs7pad(data, 16)
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
        return unpad(b''.join(plain))

    def encrypt(self, data):
        if not len(data) % 16 == 0:
            data = pkcs7pad(data, 16)
        blocks = chunk_into(data, 16)
        ciphertext = list()
        for block in blocks:
            cipherblock = ECB(self.key).encrypt(xor_with_key(block, self._state))
            ciphertext.append(cipherblock)
            self._state = cipherblock
        return b''.join(ciphertext)


def encryption_oracle(input):
    key = os.urandom(16)
    prefixlen = random.randint(5, 10)
    suffixlen = random.randint(5, 10)
    plain = os.urandom(prefixlen) + input + os.urandom(suffixlen)
    if random.getrandbits(1):
        cipher = ECB(key)
    else:
        cipher = CBC(key, os.urandom(16))
    return cipher.encrypt(plain)


def deterministic_oracle(input, suffix):
    key = b'YELLOW SUBMARINE'
    return (ECB(key).encrypt(input + suffix))


def c14_oracle(input):
    key = b'YELLOW SUBMARINE'
    prefix = os.urandom(random.randint(1, 32))
    return ECB(key).encrypt(prefix + input + 'password:panssari-vaunu')
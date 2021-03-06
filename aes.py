import logging
import random
import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from tools import chunk_into, xor_with_key, pkcs7pad, unpad


BLOCKSIZE = 16

logger = logging.getLogger(__name__)


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


class CTR(object):
    def __init__(self, key, nonce=0):
        self.key = key
        self.nonce = nonce
        self.counter = 0
        self.cipher = ECB(self.key)

    def encrypt(self, data):
        ret = list()
        blocks = chunk_into(data, BLOCKSIZE)
        for i, block in enumerate(blocks):
            _ks = self.cipher.encrypt(struct.pack('<2Q', self.nonce, i))
            logger.debug(block)
            logger.debug(_ks)
            ret.append(xor_with_key(block, _ks))
        return b''.join(ret)


def encryption_oracle(data):
    key = os.urandom(16)
    prefixlen = random.randint(5, 10)
    suffixlen = random.randint(5, 10)
    plain = os.urandom(prefixlen) + data + os.urandom(suffixlen)
    if random.getrandbits(1):
        cipher = ECB(key)
    else:
        cipher = CBC(key, os.urandom(16))
    return cipher.encrypt(plain)


def deterministic_oracle(data, suffix):
    key = b'YELLOW SUBMARINE'
    return ECB(key).encrypt(data + suffix)


class C14Oracle(object):
    def __init__(self, secret=b'password:panssari-vaunu'):
        self.secret = secret
        self.key = b'YELLOW SUBMARINE'
        self.prefix = os.urandom(random.randint(1, 128))
        logger.info(len(self.prefix))

    def __call__(self, data, *args, **kwargs):
        plain = self.prefix + data + self.secret
        return ECB(self.key).encrypt(pkcs7pad(plain, 16))

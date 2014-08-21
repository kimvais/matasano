import base64
import logging
import os
import random

import aes
from tools import chunk_into, unpad, pkcs7pad


BLOCKSIZE = 16

__author__ = 'kimvais'

PLAINTEXTS = [base64.b64decode(x) for x in
              """MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93""".splitlines()]

KEY = b'YELLOW SUBMARINE'

logger = logging.getLogger(__name__)


def encrypt():
    plain = random.choice(PLAINTEXTS)
    iv = os.urandom(BLOCKSIZE)
    c = aes.CBC(KEY, iv)
    return iv + c.encrypt(pkcs7pad(plain, BLOCKSIZE))


def padding_oracle(data):
    iv = data[:BLOCKSIZE]
    ct = data[BLOCKSIZE:]
    c = aes.CBC(KEY, iv)
    try:
        c.decrypt(ct)
        return True
    except ValueError:
        return False


def main():
    ct = encrypt()
    iv, *blocks = chunk_into(ct, BLOCKSIZE)
    logger.info(iv)
    logger.info(blocks)
    ret = list()
    prev_block = iv
    for block in blocks:
        known = list()
        while len(known) < BLOCKSIZE:
            i = len(known)
            known_trailer = bytes((ord(x) ^ y ^ (i + 1)) for x, y in (zip(known, prev_block[-i:])))
            logger.debug("Trailer: {}".format(known_trailer))
            for c in range(256):
                char = bytes((c,))
                fake_block = b'\x00' * (BLOCKSIZE - len(known_trailer) - 1) + char + known_trailer
                if padding_oracle(fake_block + block):
                    Ca = char[0]
                    padsize = len(known) + 1
                    known.insert(0, bytes((Ca ^ prev_block[-padsize] ^ padsize,)))
                    logger.info('Decrypted: {}'.format(b''.join(known)))
                    break
        ret.extend(known)
        prev_block = block
    return unpad(b''.join(ret))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(name)s.%(funcName)s:[%(lineno)s]: %(message)s')
    logger.info(main())




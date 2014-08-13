import logging

import math
from aes import encryption_oracle, deterministic_oracle
from tools import chunk_into, unpad


__author__ = 'kimvais'

logger = logging.getLogger(__name__)


def analyze(plain, chunk_count):
    analyzed = len(set(chunk_into(encryption_oracle(plain), 16)))
    if chunk_count > analyzed:
        return 'ECB'
    else:
        return 'CBC'


def challenge_11():
    plain = b'foobar' * 20
    chunk_count = math.ceil(len(plain) / 16)
    for _ in range(50):
        print(analyze(plain, chunk_count))


def detect_blocksize():
    for i in range(3, 65):
        plain = b'A' * 64
        cipher = deterministic_oracle(plain)
        chunks = chunk_into(cipher, i)
        if chunks[0] == chunks[1]:
            logger.info('Block size = {}'.format(i))
            return i


def challenge_12():
    blocksize = detect_blocksize()
    x = 2 * blocksize * b'A'
    ciphertext = deterministic_oracle(x)
    chunks = chunk_into(ciphertext, blocksize)
    if len(chunks) > len(set(chunks)):
        logger.info("Cipher is running in ECB mode")
    datalen = len(deterministic_oracle(b''))
    logger.critical(datalen)
    known = list()
    for offset in range(1, datalen):
        padder = (datalen - offset) * b'A'
        rtable = dict()
        for c in range(256):
            char = bytes((c,))
            plain = padder + b''.join(known) + char
            logger.debug(plain)
            rtable[deterministic_oracle(plain)[:datalen]] = char
        ciphertext = deterministic_oracle(padder)
        try:
            known.append(rtable[ciphertext[:datalen]])
        except KeyError:
            return(unpad(b''.join(known)))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # challenge_11()
    print(challenge_12())

from base64 import b64decode
import base64
import logging
import string

import math
from aes import encryption_oracle, deterministic_oracle, ECB, C14Oracle
from tools import chunk_into, unpad, UserProfile, pkcs7pad


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


def detect_blocksize(suffix):
    for i in range(3, 65):
        plain = b'A' * 64
        cipher = deterministic_oracle(plain, suffix)
        chunks = chunk_into(cipher, i)
        if chunks[0] == chunks[1]:
            logger.info('Block size = {}'.format(i))
            return i


def challenge_12():
    with open('12.txt') as f:
        suffix = b64decode(f.read())
    blocksize = detect_blocksize(suffix)
    x = 2 * blocksize * b'A'
    ciphertext = deterministic_oracle(x, suffix)
    chunks = chunk_into(ciphertext, blocksize)
    if len(chunks) > len(set(chunks)):
        logger.info("Cipher is running in ECB mode")
    datalen = len(deterministic_oracle(b'', suffix))
    logger.critical(datalen)
    known = list()
    for offset in range(1, datalen):
        padder = (datalen - offset) * b'A'
        rtable = dict()
        for c in range(256):
            char = bytes((c,))
            plain = padder + b''.join(known) + char
            # logger.debug(plain)
            rtable[deterministic_oracle(plain, suffix)[:datalen]] = char
        ciphertext = deterministic_oracle(padder, suffix)
        try:
            known.append(rtable[ciphertext[:datalen]])
        except KeyError:
            return (unpad(b''.join(known)))


def kvparse(input):
    d = dict(x.split(b'=') for x in input.split(b'&'))
    return UserProfile(d)


def profile_for(email):
    if not isinstance(email, bytes):
        email = email.encode('ascii')
    key = base64.b64decode(b'XJeZGgXzH89F0q1vTJfTgw==')
    if b'&' in email or b'=' in email:
        raise ValueError("Invalid e-mail {}".format(email))
    else:
        s = UserProfile(dict(email=email, uid=10, role='user')).serialize()
        assert s is not None
        return ECB(key).encrypt(s)


def parse_profile(ciphertext):
    key = base64.b64decode(b'XJeZGgXzH89F0q1vTJfTgw==')
    plaintext = unpad(ECB(key).decrypt(ciphertext))
    logger.critical(plaintext)
    return kvparse(plaintext)


def challenge_13():
    min_len = len(profile_for(''))
    for i in range(16):
        if len(profile_for('x' * i)) > min_len:
            break
    spacing = i
    chunks = chunk_into(profile_for(spacing * b'x' + pkcs7pad(b'admin', 16)), 16)
    cut = chunk_into(profile_for(spacing * b'x' + pkcs7pad(b'user', 16)), 16)[1]
    paste = chunks[1]
    for i in range(16):
        chunks = chunk_into(profile_for(i * b'x'), 16)
        if chunks[-1] == cut:
            chunks[-1] = paste
            return parse_profile(b''.join(chunks)).items()


def challenge_14():
    oracle = C14Oracle()
    minimal_ct = oracle(b'')
    min_len = len(minimal_ct)
    for i in range(32):
        if len(oracle(b'x' * i)) > min_len:
            break
    logger.debug('Minimal padding: {}'.format(i))
    x = i + 17
    # for i in range(16 * 3):
    #     ct = oracle(b'x' * i)
    #     chunks = chunk_into(ct, 16)
    #     if len(chunks) > len(set(chunks)):
    #         y = i - 16
    #         break
    known = list()
    while x:
        chunks = chunk_into(oracle(b'x' * x), 16)
        gold = chunks[-1]
        for c in string.printable:
            char = bytes(c, 'ascii')
            plain = (x - 3) * b'x' + pkcs7pad(char, 16)
            ct = oracle(plain)
            chunks = chunk_into(ct, 16)
            # for i, chunk in enumerate(chunks):
            if gold == chunks[-2]:
                logger.debug(chunks)
                logger.debug(gold)
                logger.info('last letter: {}'.format(char))
                known.append(char)
                x = False
                break


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s.%(funcName)s:[%(lineno)s]: %(message)s')
    #print(challenge_11())
    #print(challenge_12())
    #print(challenge_13())
    print(challenge_14())

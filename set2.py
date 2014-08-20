from base64 import b64decode
import base64
import logging
import string

import math
from aes import encryption_oracle, deterministic_oracle, ECB, C14Oracle
from tools import chunk_into, unpad, UserProfile, pkcs7pad


__author__ = 'kimvais'

logger = logging.getLogger(__name__)
BLOCKSIZE = 16


def analyze(plain, chunk_count):
    analyzed = len(set(chunk_into(encryption_oracle(plain), BLOCKSIZE)))
    if chunk_count > analyzed:
        return 'ECB'
    else:
        return 'CBC'


def challenge_11():
    plain = b'foobar' * 20
    chunk_count = math.ceil(len(plain) / BLOCKSIZE)
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
    for i in range(BLOCKSIZE):
        if len(profile_for('x' * i)) > min_len:
            break
    spacing = i
    chunks = chunk_into(profile_for(spacing * b'x' + pkcs7pad(b'admin', BLOCKSIZE)), BLOCKSIZE)
    cut = chunk_into(profile_for(spacing * b'x' + pkcs7pad(b'user', BLOCKSIZE)), BLOCKSIZE)[1]
    paste = chunks[1]
    for i in range(BLOCKSIZE):
        chunks = chunk_into(profile_for(i * b'x'), BLOCKSIZE)
        if chunks[-1] == cut:
            chunks[-1] = paste
            return parse_profile(b''.join(chunks)).items()


def challenge_14():
    oracle = C14Oracle()
    minimal_ct = oracle(b'')
    min_len = len(minimal_ct)
    logger.info("CT with empty payload {}: {}".format(min_len, minimal_ct))
    pushout = hdr = None
    prefix_pad_to_block_boundary = 0
    for i in range(1, BLOCKSIZE + 1):
        pairs = zip(chunk_into(oracle(i * b'x'), BLOCKSIZE), chunk_into(oracle(i * b'y'), BLOCKSIZE))
        chunk_equality = [a == b for a, b in pairs]
        if hdr is None:
            hdr = chunk_equality.index(False) + 1
        falses = chunk_equality.count(False)
        logger.debug('i: {}, {}'.format(i, falses))
        logger.debug(chunk_equality)
        if not prefix_pad_to_block_boundary and falses > 1:
            prefix_pad_to_block_boundary = i - 1
        if pushout is None and len(chunk_equality) > min_len / BLOCKSIZE:
            pushout = i + 1
    prefix_len = hdr * BLOCKSIZE - prefix_pad_to_block_boundary
    plaintext_len = min_len - prefix_len - pushout + 1
    discard = hdr * BLOCKSIZE
    logger.info('Prefix len: {}'.format(prefix_len))
    logger.info('Plaintext len: {}'.format(plaintext_len))
    logger.info('Prefix pad to block boundary: {}'.format(prefix_pad_to_block_boundary))
    logger.info('Discard: {}'.format(discard))
    known = list()
    logger.info('Push out: {}'.format(pushout))
    goldindex = min_len
    while len(known) < plaintext_len:
        insert = (len(known) + pushout) * b'x'
        ct = oracle(insert)
        gold = ct[goldindex:]
        for c in string.printable:
            char = bytes((ord(c),))
            filler = prefix_pad_to_block_boundary * b'x'
            plaintext = pkcs7pad(char + b''.join(known), BLOCKSIZE)
            compare_to = oracle(filler + plaintext)[discard:]
            # assert len(compare_to) == len(gold)
            # logger.info(compare_to)
            if compare_to.startswith(gold):
                known.insert(0, char)
                break
            logger.debug(known)

    return b''.join(known)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s.%(funcName)s:[%(lineno)s]: %(message)s')
    print(challenge_11())
    print(challenge_12())
    print(challenge_13())
    print(challenge_14())
